/**
 * @name brotli-223d80cfbec8fd346e32906c732c8ede21f0cea6-SortHuffmanTreeItems
 * @id cpp/brotli/223d80cfbec8fd346e32906c732c8ede21f0cea6/SortHuffmanTreeItems
 * @description brotli-223d80cfbec8fd346e32906c732c8ede21f0cea6-c/enc/entropy_encode.h-SortHuffmanTreeItems CVE-2020-8927
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vgaps_84, VariableAccess target_0) {
		target_0.getTarget()=vgaps_84
}

predicate func_1(Function func, DeclStmt target_1) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

from Function func, Variable vgaps_84, VariableAccess target_0, DeclStmt target_1
where
func_0(vgaps_84, target_0)
and func_1(func, target_1)
and vgaps_84.getType().hasName("const size_t[]")
and vgaps_84.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
