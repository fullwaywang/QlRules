/**
 * @name libxml2-2554a2408e09f13652049e5ffb0d26196b02ebab-xmlBufferResize
 * @id cpp/libxml2/2554a2408e09f13652049e5ffb0d26196b02ebab/xmlBufferResize
 * @description libxml2-2554a2408e09f13652049e5ffb0d26196b02ebab-tree.c-xmlBufferResize CVE-2022-29824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_7444, Parameter vsize_7444, Variable vnewSize_7446, PointerFieldAccess target_11, SwitchStmt target_12, RelationalOperation target_13, RelationalOperation target_14, RelationalOperation target_15) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7444
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewSize_7446
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_7444
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967285"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(AddExpr).getValue()="4294967295"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_7444
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(Literal).getValue()="10"
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewSize_7446
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7444
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_11
		and target_12.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_15.getGreaterOperand().(VariableAccess).getLocation()))
}

/*predicate func_1(Parameter vsize_7444, RelationalOperation target_14, ExprStmt target_16) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vsize_7444
		and target_1.getLesserOperand().(SubExpr).getValue()="4294967285"
		and target_14.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(VariableAccess).getLocation())
		and target_1.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_3(Parameter vsize_7444, Variable vnewSize_7446, RelationalOperation target_17) {
	exists(ConditionalExpr target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_7444
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967285"
		and target_3.getThen().(AddExpr).getValue()="4294967295"
		and target_3.getElse() instanceof AddExpr
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewSize_7446
		and target_17.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_4(PointerFieldAccess target_11, Function func) {
	exists(EmptyStmt target_4 |
		target_4.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_11
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vsize_7444, Variable vnewSize_7446, RelationalOperation target_15, ExprStmt target_20) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(VariableAccess).getTarget()=vnewSize_7446
		and target_5.getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_7444
		and target_5.getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967285"
		and target_5.getRValue().(ConditionalExpr).getThen().(AddExpr).getValue()="4294967295"
		and target_5.getRValue().(ConditionalExpr).getElse() instanceof AddExpr
		and target_15.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_20.getExpr().(AssignMulExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getLValue().(VariableAccess).getLocation()))
}

predicate func_6(PointerFieldAccess target_11, Function func) {
	exists(EmptyStmt target_6 |
		target_6.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_11
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Parameter vbuf_7444, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="size"
		and target_7.getQualifier().(VariableAccess).getTarget()=vbuf_7444
}

predicate func_8(Parameter vbuf_7444, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="size"
		and target_8.getQualifier().(VariableAccess).getTarget()=vbuf_7444
}

predicate func_9(Parameter vsize_7444, Variable vnewSize_7446, AddExpr target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vsize_7444
		and target_9.getAnOperand().(Literal).getValue()="10"
		and target_9.getParent().(AssignExpr).getRValue() = target_9
		and target_9.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewSize_7446
}

predicate func_10(Parameter vsize_7444, Variable vnewSize_7446, AddExpr target_10) {
		target_10.getAnOperand().(VariableAccess).getTarget()=vsize_7444
		and target_10.getAnOperand().(Literal).getValue()="10"
		and target_10.getParent().(AssignExpr).getRValue() = target_10
		and target_10.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewSize_7446
}

predicate func_11(Parameter vbuf_7444, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="alloc"
		and target_11.getQualifier().(VariableAccess).getTarget()=vbuf_7444
}

predicate func_12(Parameter vbuf_7444, Parameter vsize_7444, Variable vnewSize_7446, SwitchStmt target_12) {
		target_12.getExpr().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_12.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7444
		and target_12.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewSize_7446
		and target_12.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="size"
		and target_12.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7444
		and target_12.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="size"
		and target_12.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7444
		and target_12.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_7444
		and target_12.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(Literal).getValue()="10"
}

predicate func_13(Parameter vbuf_7444, RelationalOperation target_13) {
		 (target_13 instanceof GTExpr or target_13 instanceof LTExpr)
		and target_13.getLesserOperand().(PointerFieldAccess).getTarget().getName()="use"
		and target_13.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7444
		and target_13.getGreaterOperand().(Literal).getValue()="4096"
}

predicate func_14(Parameter vsize_7444, RelationalOperation target_14) {
		 (target_14 instanceof GTExpr or target_14 instanceof LTExpr)
		and target_14.getGreaterOperand().(VariableAccess).getTarget()=vsize_7444
		and target_14.getLesserOperand().(SubExpr).getValue()="4294967285"
}

predicate func_15(Parameter vsize_7444, Variable vnewSize_7446, RelationalOperation target_15) {
		 (target_15 instanceof GTExpr or target_15 instanceof LTExpr)
		and target_15.getGreaterOperand().(VariableAccess).getTarget()=vsize_7444
		and target_15.getLesserOperand().(VariableAccess).getTarget()=vnewSize_7446
}

predicate func_16(Parameter vbuf_7444, Parameter vsize_7444, Variable vnewSize_7446, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewSize_7446
		and target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="size"
		and target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7444
		and target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="size"
		and target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7444
		and target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_7444
		and target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(Literal).getValue()="10"
}

predicate func_17(Parameter vsize_7444, Variable vnewSize_7446, RelationalOperation target_17) {
		 (target_17 instanceof GTExpr or target_17 instanceof LTExpr)
		and target_17.getGreaterOperand().(VariableAccess).getTarget()=vsize_7444
		and target_17.getLesserOperand().(VariableAccess).getTarget()=vnewSize_7446
}

predicate func_20(Variable vnewSize_7446, ExprStmt target_20) {
		target_20.getExpr().(AssignMulExpr).getLValue().(VariableAccess).getTarget()=vnewSize_7446
		and target_20.getExpr().(AssignMulExpr).getRValue().(Literal).getValue()="2"
}

from Function func, Parameter vbuf_7444, Parameter vsize_7444, Variable vnewSize_7446, PointerFieldAccess target_7, PointerFieldAccess target_8, AddExpr target_9, AddExpr target_10, PointerFieldAccess target_11, SwitchStmt target_12, RelationalOperation target_13, RelationalOperation target_14, RelationalOperation target_15, ExprStmt target_16, RelationalOperation target_17, ExprStmt target_20
where
not func_0(vbuf_7444, vsize_7444, vnewSize_7446, target_11, target_12, target_13, target_14, target_15)
and not func_3(vsize_7444, vnewSize_7446, target_17)
and not func_4(target_11, func)
and not func_5(vsize_7444, vnewSize_7446, target_15, target_20)
and not func_6(target_11, func)
and func_7(vbuf_7444, target_7)
and func_8(vbuf_7444, target_8)
and func_9(vsize_7444, vnewSize_7446, target_9)
and func_10(vsize_7444, vnewSize_7446, target_10)
and func_11(vbuf_7444, target_11)
and func_12(vbuf_7444, vsize_7444, vnewSize_7446, target_12)
and func_13(vbuf_7444, target_13)
and func_14(vsize_7444, target_14)
and func_15(vsize_7444, vnewSize_7446, target_15)
and func_16(vbuf_7444, vsize_7444, vnewSize_7446, target_16)
and func_17(vsize_7444, vnewSize_7446, target_17)
and func_20(vnewSize_7446, target_20)
and vbuf_7444.getType().hasName("xmlBufferPtr")
and vsize_7444.getType().hasName("unsigned int")
and vnewSize_7446.getType().hasName("unsigned int")
and vbuf_7444.getFunction() = func
and vsize_7444.getFunction() = func
and vnewSize_7446.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
