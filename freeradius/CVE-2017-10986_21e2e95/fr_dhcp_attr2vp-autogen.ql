/**
 * @name freeradius-21e2e95751bfb54c0fb0328392d06671a75c191c-fr_dhcp_attr2vp
 * @id cpp/freeradius/21e2e95751bfb54c0fb0328392d06671a75c191c/fr-dhcp-attr2vp
 * @description freeradius-21e2e95751bfb54c0fb0328392d06671a75c191c-src/modules/proto_dhcp/dhcp.c-fr_dhcp_attr2vp CVE-2017-10986
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vq_761, NotExpr target_16, VariableAccess target_0) {
		target_0.getTarget()=vq_761
		and target_0.getLocation().isBefore(target_16.getOperand().(VariableAccess).getLocation())
}

predicate func_1(Variable vvp_724, Literal target_1) {
		target_1.getValue()="824"
		and not target_1.getValue()="822"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fr_strerror_printf")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="Internal sanity check %d %d"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="type"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="da"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvp_724
}

predicate func_2(Variable vvp_724, Variable vp_760, Variable vq_761, Variable vend_761, ExprStmt target_17, PointerArithmeticOperation target_18, RelationalOperation target_4, ExprStmt target_19) {
	exists(WhileStmt target_2 |
		target_2.getCondition() instanceof RelationalOperation
		and target_2.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vq_761
		and target_2.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("memchr")
		and target_2.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_760
		and target_2.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(CharLiteral).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getType().hasName("const uint8_t *")
		and target_2.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_760
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vq_761
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vq_761
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vend_761
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fr_pair_value_bstrncpy")
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvp_724
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_760
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vq_761
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_760
		and target_2.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_760
		and target_2.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vq_761
		and target_2.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_760
		and target_2.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vend_761
		and target_2.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen() instanceof BreakStmt
		and target_2.getStmt().(BlockStmt).getStmt(5) instanceof ExprStmt
		and target_2.getStmt().(BlockStmt).getStmt(6) instanceof IfStmt
		and target_2.getStmt().(BlockStmt).getStmt(7) instanceof ExprStmt
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_18.getRightOperand().(VariableAccess).getLocation().isBefore(target_2.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getLesserOperand().(VariableAccess).getLocation())
		and target_19.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_3(Variable vp_760, Variable vend_761, BlockStmt target_20, ExprStmt target_21, RelationalOperation target_4, ExprStmt target_22) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vp_760
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vend_761
		and target_3.getParent().(IfStmt).getThen()=target_20
		and target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(VariableAccess).getLocation())
		and target_3.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getLesserOperand().(VariableAccess).getLocation())
		and target_22.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(VariableAccess).getLocation()))
}

*/
predicate func_4(Variable vp_760, Variable vend_761, BlockStmt target_20, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vp_760
		and target_4.getGreaterOperand().(VariableAccess).getTarget()=vend_761
		and target_4.getParent().(IfStmt).getThen()=target_20
}

predicate func_5(Variable vvp_724, Parameter vctx_722, RelationalOperation target_4, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvp_724
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("fr_pair_afrom_da")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_722
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="da"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvp_724
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_6(Parameter vvp_p_722, Variable vvp_724, RelationalOperation target_4, IfStmt target_6) {
		target_6.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vvp_724
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fr_pair_list_free")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvp_p_722
		and target_6.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_7(Variable vvp_724, Variable vcursor_762, RelationalOperation target_4, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("fr_cursor_insert")
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcursor_762
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvp_724
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_8(Function func, BreakStmt target_8) {
		target_8.toString() = "break;"
		and target_8.getEnclosingFunction() = func
}

predicate func_9(PointerFieldAccess target_23, Function func, BreakStmt target_9) {
		target_9.toString() = "break;"
		and target_9.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_23
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Function func, LabelStmt target_10) {
		target_10.toString() = "label ...:"
		and target_10.getEnclosingFunction() = func
}

predicate func_11(Function func, LabelStmt target_11) {
		target_11.toString() = "label ...:"
		and target_11.getEnclosingFunction() = func
}

predicate func_12(PointerFieldAccess target_23, Function func, LabelStmt target_12) {
		target_12.toString() = "label ...:"
		and target_12.getName() ="raw"
		and target_12.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_23
		and target_12.getEnclosingFunction() = func
}

predicate func_13(Variable vvp_724, Variable vp_760, Variable vq_761, Variable vend_761, ForStmt target_13) {
		target_13.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vq_761
		and target_13.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("memchr")
		and target_13.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_760
		and target_13.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(CharLiteral).getValue()="0"
		and target_13.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vq_761
		and target_13.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_760
		and target_13.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vq_761
		and target_13.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vq_761
		and target_13.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vend_761
		and target_13.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fr_pair_value_bstrncpy")
		and target_13.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvp_724
		and target_13.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_760
		and target_13.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vq_761
		and target_13.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_760
		and target_13.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_760
		and target_13.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vq_761
		and target_13.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_13.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition() instanceof RelationalOperation
		and target_13.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_13.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_13.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_13.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(3).(ContinueStmt).toString() = "continue;"
		and target_13.getStmt().(BlockStmt).getStmt(5) instanceof BreakStmt
		and target_13.getStmt().(BlockStmt).getStmt(6) instanceof LabelStmt
}

/*predicate func_14(RelationalOperation target_4, Function func, ContinueStmt target_14) {
		target_14.toString() = "continue;"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_14.getEnclosingFunction() = func
}

*/
predicate func_15(Function func, LabelStmt target_15) {
		target_15.toString() = "label ...:"
		and target_15.getEnclosingFunction() = func
}

predicate func_16(Variable vq_761, NotExpr target_16) {
		target_16.getOperand().(VariableAccess).getTarget()=vq_761
}

predicate func_17(Variable vvp_724, Variable vp_760, Variable vq_761, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("fr_pair_value_bstrncpy")
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvp_724
		and target_17.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_760
		and target_17.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vq_761
		and target_17.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_760
}

predicate func_18(Variable vp_760, Variable vq_761, PointerArithmeticOperation target_18) {
		target_18.getLeftOperand().(VariableAccess).getTarget()=vq_761
		and target_18.getRightOperand().(VariableAccess).getTarget()=vp_760
}

predicate func_19(Variable vq_761, Variable vend_761, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vq_761
		and target_19.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_761
}

predicate func_20(BlockStmt target_20) {
		target_20.getStmt(0) instanceof ExprStmt
		and target_20.getStmt(1) instanceof IfStmt
		and target_20.getStmt(2) instanceof ExprStmt
		and target_20.getStmt(3) instanceof ContinueStmt
}

predicate func_21(Variable vp_760, Variable vq_761, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_760
		and target_21.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vq_761
		and target_21.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
}

predicate func_22(Variable vq_761, Variable vend_761, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vq_761
		and target_22.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vend_761
}

predicate func_23(Variable vvp_724, PointerFieldAccess target_23) {
		target_23.getTarget().getName()="type"
		and target_23.getQualifier().(PointerFieldAccess).getTarget().getName()="da"
		and target_23.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvp_724
}

from Function func, Parameter vvp_p_722, Variable vvp_724, Variable vp_760, Variable vq_761, Variable vend_761, Variable vcursor_762, Parameter vctx_722, VariableAccess target_0, Literal target_1, RelationalOperation target_4, ExprStmt target_5, IfStmt target_6, ExprStmt target_7, BreakStmt target_8, BreakStmt target_9, LabelStmt target_10, LabelStmt target_11, LabelStmt target_12, ForStmt target_13, LabelStmt target_15, NotExpr target_16, ExprStmt target_17, PointerArithmeticOperation target_18, ExprStmt target_19, BlockStmt target_20, ExprStmt target_21, ExprStmt target_22, PointerFieldAccess target_23
where
func_0(vq_761, target_16, target_0)
and func_1(vvp_724, target_1)
and not func_2(vvp_724, vp_760, vq_761, vend_761, target_17, target_18, target_4, target_19)
and func_4(vp_760, vend_761, target_20, target_4)
and func_5(vvp_724, vctx_722, target_4, target_5)
and func_6(vvp_p_722, vvp_724, target_4, target_6)
and func_7(vvp_724, vcursor_762, target_4, target_7)
and func_8(func, target_8)
and func_9(target_23, func, target_9)
and func_10(func, target_10)
and func_11(func, target_11)
and func_12(target_23, func, target_12)
and func_13(vvp_724, vp_760, vq_761, vend_761, target_13)
and func_15(func, target_15)
and func_16(vq_761, target_16)
and func_17(vvp_724, vp_760, vq_761, target_17)
and func_18(vp_760, vq_761, target_18)
and func_19(vq_761, vend_761, target_19)
and func_20(target_20)
and func_21(vp_760, vq_761, target_21)
and func_22(vq_761, vend_761, target_22)
and func_23(vvp_724, target_23)
and vvp_p_722.getType().hasName("VALUE_PAIR **")
and vvp_724.getType().hasName("VALUE_PAIR *")
and vp_760.getType().hasName("const uint8_t *")
and vq_761.getType().hasName("const uint8_t *")
and vend_761.getType().hasName("const uint8_t *")
and vcursor_762.getType().hasName("vp_cursor_t")
and vctx_722.getType().hasName("TALLOC_CTX *")
and vvp_p_722.getParentScope+() = func
and vvp_724.getParentScope+() = func
and vp_760.getParentScope+() = func
and vq_761.getParentScope+() = func
and vend_761.getParentScope+() = func
and vcursor_762.getParentScope+() = func
and vctx_722.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
