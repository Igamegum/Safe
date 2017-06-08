
#ifndef SAFE_XOR_ENCRYPTION_H_H
#define SAFE_XOR_ENCRYPTION_H_H

void Encrypt(const std::string input_filename,const std::string output_filename,const std::string Key)
{
	
	std::ifstream ifs;
	ifs.open(input_filename,std::ios::in|std::ios::binary);


	std::ofstream ofs;
	ofs.open(output_filename,std::ios::out|std::ios::binary);

	char ch;

	long long  index = 0;
	int length = Key.length();

	while(!ifs.eof())
	{
		ifs.read(&ch,1);
		ofs<< static_cast<char>((ch^( char )Key[index % length]));
		++index;
	}

	ifs.close();
	ofs.close();
}

#endif
