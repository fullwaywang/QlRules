/**
 * @name linux-d3b6372c5881cb54925212abb62c521df8ba4809-__del_gref
 * @id cpp/linux/d3b6372c5881cb54925212abb62c521df8ba4809/__del_gref
 * @description linux-d3b6372c5881cb54925212abb62c521df8ba4809-__del_gref CVE-2022-23039
 * @kind problem
 * @tags security
 */

import cpp

predicate func_2(Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof LongType
		and func.getEntryPoint().(BlockStmt).getStmt(0)=target_2)
}

predicate func_3(Function func) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getType().hasName("unsigned long")
		and target_3.getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerArithmeticOperation).getLeftOperand() instanceof PointerFieldAccess
		and target_3.getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getType().hasName("unsigned long")
		and target_3.getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_3.getRValue().(AddExpr).getAnOperand().(VariableAccess).getType().hasName("unsigned long")
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("gnttab_end_foreign_access")
		and target_4.getExpr().(FunctionCall).getArgument(0) instanceof PointerFieldAccess
		and target_4.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("unsigned long")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof PointerFieldAccess
		and target_4.getEnclosingFunction() = func)
}

predicate func_6(Parameter vgref_184) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="gref_id"
		and target_6.getQualifier().(VariableAccess).getTarget()=vgref_184)
}

predicate func_8(Parameter vgref_184) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("gnttab_free_grant_reference")
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="gref_id"
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgref_184
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="gref_id"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgref_184)
}

predicate func_9(Parameter vgref_184) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="page"
		and target_9.getQualifier().(VariableAccess).getTarget()=vgref_184)
}

predicate func_13(Function func) {
	exists(ReturnStmt target_13 |
		target_13.toString() = "return ..."
		and target_13.getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("gnttab_query_foreign_access")
		and target_13.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof PointerFieldAccess
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Parameter vgref_184) {
	exists(IfStmt target_14 |
		target_14.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("gnttab_end_foreign_access_ref")
		and target_14.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0) instanceof PointerFieldAccess
		and target_14.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_14.getThen().(ReturnStmt).toString() = "return ..."
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="gref_id"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgref_184)
}

predicate func_15(Function func) {
	exists(IfStmt target_15 |
		target_15.getCondition() instanceof PointerFieldAccess
		and target_15.getThen().(ExprStmt).getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_15)
}

from Function func, Parameter vgref_184
where
not func_2(func)
and not func_3(func)
and not func_4(func)
and func_6(vgref_184)
and func_8(vgref_184)
and func_9(vgref_184)
and func_13(func)
and func_14(vgref_184)
and func_15(func)
and vgref_184.getType().hasName("gntalloc_gref *")
and vgref_184.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
