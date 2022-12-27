/**
 * @name libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-xmlBufGrowInternal
 * @id cpp/libxml2/6c283d83eccd940bcde15634ac8c7f100e3caefd/xmlBufGrowInternal
 * @description libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-xmlBufGrowInternal CVE-2022-29824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vbuf_424, Parameter vlen_424) {
	exists(SubExpr target_1 |
		target_1.getLeftOperand() instanceof PointerFieldAccess
		and target_1.getRightOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_424
		and target_1.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vlen_424
		and target_1.getParent().(LTExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getParent().(LTExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_424
		and target_1.getParent().(LTExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_1.getParent().(LTExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_424)
}

predicate func_4(Parameter vbuf_424, Variable vsize_425, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition() instanceof RelationalOperation
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_425
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_424
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(Literal).getValue()="2"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse() instanceof MulExpr
		and target_4.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_425
		and target_4.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof AddExpr
		and target_4.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_425
		and target_4.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_425
		and target_4.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_4.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_4.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_4.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_425
		and target_4.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(Literal).getValue()="100"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_4))
}

predicate func_12(Parameter vbuf_424, Parameter vlen_424, Variable vsize_425) {
	exists(RelationalOperation target_12 |
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_12.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_424
		and target_12.getLesserOperand().(VariableAccess).getTarget()=vlen_424
		and target_12.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_425
		and target_12.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_12.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_424
		and target_12.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="2")
}

predicate func_15(Function func) {
	exists(Literal target_15 |
		target_15.getValue()="100"
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Parameter vbuf_424) {
	exists(PointerFieldAccess target_16 |
		target_16.getTarget().getName()="alloc"
		and target_16.getQualifier().(VariableAccess).getTarget()=vbuf_424)
}

predicate func_17(Parameter vbuf_424) {
	exists(PointerFieldAccess target_17 |
		target_17.getTarget().getName()="use"
		and target_17.getQualifier().(VariableAccess).getTarget()=vbuf_424)
}

predicate func_20(Variable vsize_425) {
	exists(AssignExpr target_20 |
		target_20.getLValue().(VariableAccess).getTarget()=vsize_425
		and target_20.getRValue().(AddExpr).getAnOperand() instanceof AddExpr
		and target_20.getRValue().(AddExpr).getAnOperand() instanceof Literal)
}

from Function func, Parameter vbuf_424, Parameter vlen_424, Variable vsize_425
where
not func_1(vbuf_424, vlen_424)
and not func_4(vbuf_424, vsize_425, func)
and func_12(vbuf_424, vlen_424, vsize_425)
and func_15(func)
and vbuf_424.getType().hasName("xmlBufPtr")
and func_16(vbuf_424)
and func_17(vbuf_424)
and vlen_424.getType().hasName("size_t")
and vsize_425.getType().hasName("size_t")
and func_20(vsize_425)
and vbuf_424.getParentScope+() = func
and vlen_424.getParentScope+() = func
and vsize_425.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
