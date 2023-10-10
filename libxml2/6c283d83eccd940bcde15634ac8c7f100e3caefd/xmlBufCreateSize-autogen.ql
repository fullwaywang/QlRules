/**
 * @name libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-xmlBufCreateSize
 * @id cpp/libxml2/6c283d83eccd940bcde15634ac8c7f100e3caefd/xmlBufCreateSize
 * @description libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-buf.c-xmlBufCreateSize CVE-2022-29824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsize_151, Literal target_0) {
		target_0.getValue()="2"
		and not target_0.getValue()="1"
		and target_0.getParent().(AddExpr).getParent().(ConditionalExpr).getThen().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_151
}

predicate func_1(Parameter vsize_151, ExprStmt target_2, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsize_151
		and target_1.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="18446744073709551615"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_1)
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vsize_151, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlBufPtr")
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vsize_151
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_151
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(AddExpr).getAnOperand() instanceof Literal
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

from Function func, Parameter vsize_151, Literal target_0, ExprStmt target_2
where
func_0(vsize_151, target_0)
and not func_1(vsize_151, target_2, func)
and func_2(vsize_151, target_2)
and vsize_151.getType().hasName("size_t")
and vsize_151.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
