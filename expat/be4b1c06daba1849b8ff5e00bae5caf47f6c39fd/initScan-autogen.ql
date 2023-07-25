/**
 * @name expat-be4b1c06daba1849b8ff5e00bae5caf47f6c39fd-initScan
 * @id cpp/expat/be4b1c06daba1849b8ff5e00bae5caf47f6c39fd/initScan
 * @description expat-be4b1c06daba1849b8ff5e00bae5caf47f6c39fd-expat/lib/xmltok.c-initScan CVE-2016-0718
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vptr_1511, Parameter vend_1512, ReturnStmt target_4, EqualityOperation target_5) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vptr_1511
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vend_1512
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_0.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_1(Parameter vptr_1511, Parameter vend_1512, ReturnStmt target_4, VariableAccess target_1) {
		target_1.getTarget()=vptr_1511
		and target_1.getParent().(EQExpr).getAnOperand().(VariableAccess).getTarget()=vend_1512
		and target_1.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_4
}

*/
/*predicate func_2(Parameter vptr_1511, Parameter vend_1512, ReturnStmt target_4, VariableAccess target_2) {
		target_2.getTarget()=vend_1512
		and target_2.getParent().(EQExpr).getAnOperand().(VariableAccess).getTarget()=vptr_1511
		and target_2.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_4
}

*/
predicate func_3(Parameter vptr_1511, Parameter vend_1512, ReturnStmt target_4, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vptr_1511
		and target_3.getAnOperand().(VariableAccess).getTarget()=vend_1512
		and target_3.getParent().(IfStmt).getThen()=target_4
}

predicate func_4(ReturnStmt target_4) {
		target_4.getExpr().(UnaryMinusExpr).getValue()="-4"
}

predicate func_5(Parameter vptr_1511, Parameter vend_1512, EqualityOperation target_5) {
		target_5.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr_1511
		and target_5.getAnOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_5.getAnOperand().(VariableAccess).getTarget()=vend_1512
}

from Function func, Parameter vptr_1511, Parameter vend_1512, EqualityOperation target_3, ReturnStmt target_4, EqualityOperation target_5
where
not func_0(vptr_1511, vend_1512, target_4, target_5)
and func_3(vptr_1511, vend_1512, target_4, target_3)
and func_4(target_4)
and func_5(vptr_1511, vend_1512, target_5)
and vptr_1511.getType().hasName("const char *")
and vend_1512.getType().hasName("const char *")
and vptr_1511.getParentScope+() = func
and vend_1512.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
