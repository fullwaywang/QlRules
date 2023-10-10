/**
 * @name libxml2-2554a2408e09f13652049e5ffb0d26196b02ebab-xmlBufferCreateStatic
 * @id cpp/libxml2/2554a2408e09f13652049e5ffb0d26196b02ebab/xmlBufferCreateStatic
 * @description libxml2-2554a2408e09f13652049e5ffb0d26196b02ebab-tree.c-xmlBufferCreateStatic CVE-2022-29824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsize_7169, LogicalOrExpr target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_7169
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="4294967295"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0)
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsize_7169, LogicalOrExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("void *")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsize_7169
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Parameter vsize_7169, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="use"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlBufferPtr")
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsize_7169
}

from Function func, Parameter vsize_7169, LogicalOrExpr target_1, ExprStmt target_2
where
not func_0(vsize_7169, target_1, target_2, func)
and func_1(vsize_7169, target_1)
and func_2(vsize_7169, target_2)
and vsize_7169.getType().hasName("size_t")
and vsize_7169.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
