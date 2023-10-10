/**
 * @name libxml2-2554a2408e09f13652049e5ffb0d26196b02ebab-xmlBufferCreateSize
 * @id cpp/libxml2/2554a2408e09f13652049e5ffb0d26196b02ebab/xmlBufferCreateSize
 * @description libxml2-2554a2408e09f13652049e5ffb0d26196b02ebab-tree.c-xmlBufferCreateSize CVE-2022-29824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsize_7104, Literal target_0) {
		target_0.getValue()="2"
		and not target_0.getValue()="1"
		and target_0.getParent().(AddExpr).getParent().(ConditionalExpr).getThen().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_7104
}

predicate func_1(Parameter vsize_7104, ExprStmt target_2, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_7104
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="4294967295"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_1)
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vsize_7104, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlBufferPtr")
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vsize_7104
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_7104
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(AddExpr).getAnOperand() instanceof Literal
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

from Function func, Parameter vsize_7104, Literal target_0, ExprStmt target_2
where
func_0(vsize_7104, target_0)
and not func_1(vsize_7104, target_2, func)
and func_2(vsize_7104, target_2)
and vsize_7104.getType().hasName("size_t")
and vsize_7104.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
