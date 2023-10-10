/**
 * @name libxml2-2554a2408e09f13652049e5ffb0d26196b02ebab-xmlBufGrowInternal
 * @id cpp/libxml2/2554a2408e09f13652049e5ffb0d26196b02ebab/xmlBufGrowInternal
 * @description libxml2-2554a2408e09f13652049e5ffb0d26196b02ebab-buf.c-xmlBufGrowInternal CVE-2022-29824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_437, ReturnStmt target_15, RelationalOperation target_16) {
	exists(SubExpr target_0 |
		target_0.getLeftOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_0.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
		and target_0.getRightOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_0.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
		and target_0.getParent().(LTExpr).getLesserOperand() instanceof AddExpr
		and target_0.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_0.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
		and target_0.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_15
		and target_16.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vbuf_437, Parameter vlen_437, SubExpr target_17, RelationalOperation target_8, RelationalOperation target_16) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vlen_437
		and target_1.getLesserOperand().(SubExpr).getLeftOperand().(UnaryMinusExpr).getValue()="18446744073709551615"
		and target_1.getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_1.getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof AssignExpr
		and target_17.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(RelationalOperation target_8, Function func) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getCondition()=target_8
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vsize_438, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition() instanceof RelationalOperation
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_438
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(UnaryMinusExpr).getValue()="18446744073709551615"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse() instanceof MulExpr
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_438
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof AddExpr
		and target_3.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_438
		and target_3.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_438
		and target_3.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(UnaryMinusExpr).getValue()="18446744073709551615"
		and target_3.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_438
		and target_3.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(Literal).getValue()="100"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_3))
}

/*predicate func_4(Parameter vbuf_437, Variable vsize_438, RelationalOperation target_8) {
	exists(ConditionalExpr target_4 |
		target_4.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="9223372036854775807"
		and target_4.getThen().(UnaryMinusExpr).getValue()="18446744073709551615"
		and target_4.getElse() instanceof MulExpr
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_438
		and target_8.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_7(Parameter vbuf_437, Parameter vlen_437, ReturnStmt target_15, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="size"
		and target_7.getQualifier().(VariableAccess).getTarget()=vbuf_437
		and target_7.getParent().(LTExpr).getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_7.getParent().(LTExpr).getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
		and target_7.getParent().(LTExpr).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_437
		and target_7.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_15
}

predicate func_8(Parameter vbuf_437, Parameter vlen_437, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_8.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
		and target_8.getLesserOperand().(VariableAccess).getTarget()=vlen_437
		and target_8.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof AssignExpr
}

predicate func_9(Parameter vbuf_437, PointerFieldAccess target_9) {
		target_9.getTarget().getName()="use"
		and target_9.getQualifier().(VariableAccess).getTarget()=vbuf_437
}

/*predicate func_10(Parameter vbuf_437, Parameter vlen_437, ReturnStmt target_15, AddExpr target_10) {
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
		and target_10.getAnOperand().(VariableAccess).getTarget()=vlen_437
		and target_10.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_10.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
		and target_10.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_15
}

*/
predicate func_11(Parameter vbuf_437, Variable vsize_438, MulExpr target_11) {
		target_11.getLeftOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_11.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
		and target_11.getRightOperand().(Literal).getValue()="2"
		and target_11.getParent().(AssignExpr).getRValue() = target_11
		and target_11.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_438
}

predicate func_13(Parameter vlen_437, VariableAccess target_13) {
		target_13.getTarget()=vlen_437
}

predicate func_14(Parameter vbuf_437, Parameter vlen_437, EqualityOperation target_20, RelationalOperation target_8, LogicalOrExpr target_21, AddExpr target_14) {
		target_14.getAnOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_14.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
		and target_14.getAnOperand().(VariableAccess).getTarget()=vlen_437
		and target_14.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_20.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getLesserOperand().(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(VariableAccess).getLocation())
		and target_14.getAnOperand().(VariableAccess).getLocation().isBefore(target_21.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
}

predicate func_15(Parameter vbuf_437, ReturnStmt target_15) {
		target_15.getExpr().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_15.getExpr().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
		and target_15.getExpr().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_15.getExpr().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
}

predicate func_16(Parameter vbuf_437, RelationalOperation target_16) {
		 (target_16 instanceof GTExpr or target_16 instanceof LTExpr)
		and target_16.getLesserOperand() instanceof AddExpr
		and target_16.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_16.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
}

predicate func_17(Parameter vbuf_437, SubExpr target_17) {
		target_17.getLeftOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_17.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
		and target_17.getRightOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_17.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
}

predicate func_20(Parameter vbuf_437, EqualityOperation target_20) {
		target_20.getAnOperand().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_20.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
}

predicate func_21(Parameter vbuf_437, Parameter vlen_437, LogicalOrExpr target_21) {
		target_21.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_21.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
		and target_21.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_437
		and target_21.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="10000000"
		and target_21.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_21.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_437
		and target_21.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="10000000"
}

from Function func, Parameter vbuf_437, Parameter vlen_437, Variable vsize_438, PointerFieldAccess target_7, RelationalOperation target_8, PointerFieldAccess target_9, MulExpr target_11, VariableAccess target_13, AddExpr target_14, ReturnStmt target_15, RelationalOperation target_16, SubExpr target_17, EqualityOperation target_20, LogicalOrExpr target_21
where
not func_0(vbuf_437, target_15, target_16)
and not func_1(vbuf_437, vlen_437, target_17, target_8, target_16)
and not func_2(target_8, func)
and not func_3(vsize_438, func)
and func_7(vbuf_437, vlen_437, target_15, target_7)
and func_8(vbuf_437, vlen_437, target_8)
and func_9(vbuf_437, target_9)
and func_11(vbuf_437, vsize_438, target_11)
and func_13(vlen_437, target_13)
and func_14(vbuf_437, vlen_437, target_20, target_8, target_21, target_14)
and func_15(vbuf_437, target_15)
and func_16(vbuf_437, target_16)
and func_17(vbuf_437, target_17)
and func_20(vbuf_437, target_20)
and func_21(vbuf_437, vlen_437, target_21)
and vbuf_437.getType().hasName("xmlBufPtr")
and vlen_437.getType().hasName("size_t")
and vsize_438.getType().hasName("size_t")
and vbuf_437.getFunction() = func
and vlen_437.getFunction() = func
and vsize_438.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
