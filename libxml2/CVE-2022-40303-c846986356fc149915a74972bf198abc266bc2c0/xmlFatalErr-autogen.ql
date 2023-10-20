/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlFatalErr
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlFatalErr
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-parser.c-xmlFatalErr CVE-2022-40303
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="Name too long use XML_PARSE_HUGE option"
		and not target_0.getValue()="Name too long"
		and target_0.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0
where
func_0(func, target_0)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
