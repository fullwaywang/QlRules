/**
 * @name libxml2-ed48d65b4d6c5cec7be035ad5eebeba873b4b955-xmlMallocAtomicLoc
 * @id cpp/libxml2/ed48d65b4d6c5cec7be035ad5eebeba873b4b955/xmlMallocAtomicLoc
 * @description libxml2-ed48d65b4d6c5cec7be035ad5eebeba873b4b955-xmlmemory.c-xmlMallocAtomicLoc CVE-2017-5130
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="xmlMallocAtomicLoc : Unsigned overflow prevented\n"
		and not target_0.getValue()="xmlMallocAtomicLoc : Unsigned overflow\n"
		and target_0.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0
where
func_0(func, target_0)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
