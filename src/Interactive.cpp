/* ********************************************************** 
 *
 * wtrace
 * 2014 - 2015  Alan Gonzalez
 *
 * ********************************************************** */

#include <iostream>
#include <string>

#include "interactive.h"

InteractiveCommandLine::InteractiveCommandLine()
{

}

void
InteractiveCommandLine::DebugEvent()
{
	std::cout << "input>";
	std::string cmd;
	std::cin >> cmd;
}


