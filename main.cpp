#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <vector>

#define STRUSE_IMPLEMENTATION
#include "struse.h"



void* load( const char* filename, size_t* size_ret )
{
	FILE* f = fopen( filename, "rb" );
	if( f ) {
		fseek( f, 0, SEEK_END );
		size_t size = ftell( f );
		fseek( f, 0, SEEK_SET );
		void* buf = malloc( size );
		if( buf ) {
			fread( buf, size, 1, f );
			if( size_ret ) { *size_ret = size; }
		}
		fclose( f );
		return buf;
	}
	return 0;
}

int save( void* buf, const char* filename, size_t size )
{
	FILE* f = fopen( filename, "wb" );
	if( f ) {
		fwrite( buf, size, 1, f );
		fclose( f );
		return 0;
	}
	return 1;
}


struct countLbl
{
	unsigned int count;
	strref label;
};

int sortCountUtil( const void* a, const void* b )
{
	return (( countLbl*)a)->count < ( ( countLbl* )b )->count ? 1 : -1;
}


// lblcount file.sym path\*.s
int main( int argc, char** argv )
{

	if( argc < 5 ) {
		printf( "usage:\nlblcount <file.sym> <$addr_min> <$addr_max> <path1\\*.s> <path2\\*.s> <path3\\*.s>\n");
		return 0;
	}

	size_t symSize;
	void* symFile = load( argv[1], &symSize );
	if( !symFile ) {
		printf( "Failed to open sym file %s\n", argv[1] );
		return 1;
	}

	char* endPtr;
	int lo = (int)strtoull( argv[ 2 ][ 0 ] == '$' ? argv[ 2 ] + 1 : argv[ 2 ], &endPtr, 16 );
	int hi = (int)strtoull( argv[ 3 ][ 0 ] == '$' ? argv[ 3 ] + 1 : argv[ 3 ], &endPtr, 16 );

	if( !lo || !hi || hi < lo ) {
		printf("Address range not understood\n");
		return 1;
	}

	strref sym((const char*)symFile, (strl_t)symSize);

	std::vector< unsigned int > hashes;
	std::vector< strref > labels;
	strref symParse = sym;
	while( !sym.is_empty() ) {
		if( strref line = sym.line() ) {
			strref label = line.split_token( '=' );
			label.trim_whitespace();
			line.trim_whitespace();
			if( label.has_prefix(".label") ) { label += 6; }
			label.skip_whitespace();
			if( label && line ) {
				if( line[0] == '$' ) { ++line; }
				
				int addr = line.ahextoi();
				if( addr >= lo && addr <= hi ) {
					unsigned int hash = label.fnv1a();
					bool found = false;
					for( size_t i = 0, n = hashes.size(); i < n; ++i ) {
						if( hash == hashes[ i ] ) {
							if( label.same_str( labels[ i ]) )
							found = true;
							break;
						}
					}
					if( !found ) {
						if( hashes.capacity() == hashes.size() ) {
							hashes.reserve( hashes.capacity() + 256 );
							labels.reserve( labels.capacity() + 256 );
						}
						hashes.push_back( hash );
						labels.push_back( label );
					}
				}
			}
		}
	}

	std::vector< unsigned int > counts;
	counts.reserve( hashes.size() );
	for( size_t i = 0, n = hashes.size(); i < n; ++i ) { counts.push_back( 0 ); }

	for( int a = 4; a < argc; ++a )
	{
		strref path = strref( argv[a] ).before_last( '\\' );
		WIN32_FIND_DATAA findData;
		HANDLE find = FindFirstFileA( argv[a], &findData );
		if( find == INVALID_HANDLE_VALUE ) { return false; }
		do
		{
			if( !(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) )
			{
				strown<MAX_PATH> file(path);
				if( file ) { file.append( '\\' ); }
				file.append( findData.cFileName );

				size_t srcSize;
				void* srcFile = load( file.c_str(), &srcSize );
				if( srcFile ) {
					strref src( (const char*)srcFile, ( strl_t )srcSize );
					while( !src.is_empty() )
					{
						int lblLen = src.len_label();
						if( lblLen ) {
							strref label( src.get(), lblLen );
							src += lblLen+1;
							unsigned int hash = label.fnv1a();
							for( size_t i = 0, n = hashes.size(); i < n; ++i ) {
								if( hash == hashes[ i ] && label.same_str( labels[ i ] ) ) {
									counts[ i ]++;
									break;
								}
							}
						} else { ++src; }
					}
					free( srcFile );
				}
			}
		} while( FindNextFileA( find, &findData ) != 0 );
		const bool success = GetLastError() == ERROR_NO_MORE_FILES;
		FindClose( find );
	}

	std::vector< countLbl > sortArray;
	sortArray.reserve( hashes.size() );

	for( size_t i = 0, n = labels.size(); i < n; ++i ) {
		countLbl lbl;
		lbl.count = counts[i];
		lbl.label = labels[i];
		sortArray.push_back( lbl );
	}

	qsort( &sortArray[0], sortArray.size(), sizeof(countLbl), sortCountUtil );
	for( size_t i = 0, n = sortArray.size(); i < n; ++i ) {
		printf( STRREF_FMT ": %d\n", STRREF_ARG( sortArray[i].label ), sortArray[i].count );
	}
	free(symFile);
	return 0;
}
