/**
 * @name libxml2-2554a2408e09f13652049e5ffb0d26196b02ebab-xmlBufCreateSize
 * @id cpp/libxml2/2554a2408e09f13652049e5ffb0d26196b02ebab/xmlBufCreateSize
 * @description libxml2-2554a2408e09f13652049e5ffb0d26196b02ebab-buf.c-xmlBufCreateSize CVE-2022-29824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsize_156, Literal target_0) {
		target_0.getValue()="2"
		and not target_0.getValue()="1"
		and target_0.getParent().(AddExpr).getParent().(ConditionalExpr).getThen().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_156
}

predicate func_1(Parameter vsize_156, ExprStmt target_4, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsize_156
		and target_1.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="18446744073709551615"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_1)
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getLocation()))
}

predicate func_2(Variable vret_157, ExprStmt target_5) {
	exists(ConditionalExpr target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_157
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_2.getThen().(Literal).getValue()="2147483647"
		and target_2.getElse().(PointerFieldAccess).getTarget().getName()="size"
		and target_2.getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_157
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="compat_size"
		and target_2.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_157
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vret_157, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="size"
		and target_3.getQualifier().(VariableAccess).getTarget()=vret_157
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="compat_size"
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_157
}

predicate func_4(Parameter vsize_156, Variable vret_157, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_157
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vsize_156
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_156
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(AddExpr).getAnOperand() instanceof Literal
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

predicate func_5(Variable vret_157, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="compat_size"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_157
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_157
}

from Function func, Parameter vsize_156, Variable vret_157, Literal target_0, PointerFieldAccess target_3, ExprStmt target_4, ExprStmt target_5
where
func_0(vsize_156, target_0)
and not func_1(vsize_156, target_4, func)
and not func_2(vret_157, target_5)
and func_3(vret_157, target_3)
and func_4(vsize_156, vret_157, target_4)
and func_5(vret_157, target_5)
and vsize_156.getType().hasName("size_t")
and vret_157.getType().hasName("xmlBufPtr")
and vsize_156.getFunction() = func
and vret_157.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
