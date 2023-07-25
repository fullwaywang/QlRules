/**
 * @name expat-be4b1c06daba1849b8ff5e00bae5caf47f6c39fd-poolAppend
 * @id cpp/expat/be4b1c06daba1849b8ff5e00bae5caf47f6c39fd/poolAppend
 * @description expat-be4b1c06daba1849b8ff5e00bae5caf47f6c39fd-expat/lib/xmlparse.c-poolAppend CVE-2016-0718
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BreakStmt target_7, Function func) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("XML_Convert_Result")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("XML_Convert_Result")
		and target_0.getParent().(IfStmt).getThen()=target_7
		and target_0.getEnclosingFunction() = func)
}

predicate func_3(Parameter venc_6198, Parameter vptr_6199, Parameter vend_6199, Parameter vpool_6198, VariableCall target_3) {
		target_3.getExpr().(PointerFieldAccess).getTarget().getName()="utf8Convert"
		and target_3.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_6198
		and target_3.getArgument(0).(VariableAccess).getTarget()=venc_6198
		and target_3.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vptr_6199
		and target_3.getArgument(2).(VariableAccess).getTarget()=vend_6199
		and target_3.getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ptr"
		and target_3.getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpool_6198
		and target_3.getArgument(4).(PointerFieldAccess).getTarget().getName()="end"
		and target_3.getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpool_6198
}

predicate func_4(Function func, ExprStmt target_4) {
		target_4.getExpr() instanceof VariableCall
		and target_4.getEnclosingFunction() = func
}

/*predicate func_5(Parameter vptr_6199, Parameter vend_6199, BreakStmt target_7, VariableAccess target_5) {
		target_5.getTarget()=vptr_6199
		and target_5.getParent().(EQExpr).getAnOperand().(VariableAccess).getTarget()=vend_6199
		and target_5.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_7
}

*/
/*predicate func_6(Parameter vptr_6199, Parameter vend_6199, BreakStmt target_7, AddressOfExpr target_8, ExprStmt target_4, VariableAccess target_6) {
		target_6.getTarget()=vend_6199
		and target_6.getParent().(EQExpr).getAnOperand().(VariableAccess).getTarget()=vptr_6199
		and target_6.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_7
		and target_8.getOperand().(VariableAccess).getLocation().isBefore(target_6.getParent().(EQExpr).getAnOperand().(VariableAccess).getLocation())
}

*/
predicate func_7(BreakStmt target_7) {
		target_7.toString() = "break;"
}

predicate func_8(Parameter vptr_6199, AddressOfExpr target_8) {
		target_8.getOperand().(VariableAccess).getTarget()=vptr_6199
}

from Function func, Parameter venc_6198, Parameter vptr_6199, Parameter vend_6199, Parameter vpool_6198, VariableCall target_3, ExprStmt target_4, BreakStmt target_7, AddressOfExpr target_8
where
not func_0(target_7, func)
and func_3(venc_6198, vptr_6199, vend_6199, vpool_6198, target_3)
and func_4(func, target_4)
and func_7(target_7)
and func_8(vptr_6199, target_8)
and venc_6198.getType().hasName("const ENCODING *")
and vptr_6199.getType().hasName("const char *")
and vend_6199.getType().hasName("const char *")
and vpool_6198.getType().hasName("STRING_POOL *")
and venc_6198.getParentScope+() = func
and vptr_6199.getParentScope+() = func
and vend_6199.getParentScope+() = func
and vpool_6198.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
