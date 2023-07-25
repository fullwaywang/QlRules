/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-userauth_keyboard_interactive
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/userauth-keyboard-interactive
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/userauth.c-userauth_keyboard_interactive CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsession_1583, Variable vrc_1589, BlockStmt target_5, FunctionCall target_6, ExprStmt target_7, EqualityOperation target_8) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vrc_1589
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="userauth_kybd_data_len"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1583
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_6.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsession_1583, EqualityOperation target_9, ExprStmt target_10, IfStmt target_11) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="userauth_kybd_num_prompts"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1583
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="userauth_kybd_num_prompts"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1583
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="100"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1583
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-41"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Too many replies for keyboard-interactive prompts"
		and target_1.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_1.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="cleanup"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(16)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vsession_1583, Variable vi_1596, RelationalOperation target_12, ExprStmt target_13, PostfixIncrExpr target_14, ArrayExpr target_15) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="length"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="userauth_kybd_responses"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1583
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1596
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(SubExpr).getValue()="18446744073709551611"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="userauth_kybd_packet_len"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1583
		and target_2.getThen() instanceof BlockStmt
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1583
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-6"
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unable to allocate memory for keyboard-interactive response packet"
		and target_2.getElse().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_2.getElse().(BlockStmt).getStmt(1).(GotoStmt).getName() ="cleanup"
		and target_12.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_15.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vsession_1583, Variable vi_1596, BlockStmt target_3) {
		target_3.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_kybd_packet_len"
		and target_3.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1583
		and target_3.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="4"
		and target_3.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="length"
		and target_3.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="userauth_kybd_responses"
		and target_3.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1596
}

predicate func_4(Variable vrc_1589, BlockStmt target_5, VariableAccess target_4) {
		target_4.getTarget()=vrc_1589
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(Parameter vsession_1583, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_kybd_state"
		and target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1583
		and target_5.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_5.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1583
		and target_5.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-18"
		and target_5.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Waiting for keyboard USERAUTH response"
}

predicate func_6(Parameter vsession_1583, FunctionCall target_6) {
		target_6.getTarget().hasName("_libssh2_error")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vsession_1583
		and target_6.getArgument(1).(UnaryMinusExpr).getValue()="-37"
		and target_6.getArgument(2).(StringLiteral).getValue()="Would block"
}

predicate func_7(Parameter vsession_1583, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_kybd_state"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1583
}

predicate func_8(Variable vrc_1589, EqualityOperation target_8) {
		target_8.getAnOperand().(VariableAccess).getTarget()=vrc_1589
		and target_8.getAnOperand().(UnaryMinusExpr).getValue()="-37"
}

predicate func_9(Parameter vsession_1583, EqualityOperation target_9) {
		target_9.getAnOperand().(PointerFieldAccess).getTarget().getName()="userauth_kybd_state"
		and target_9.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1583
}

predicate func_10(Parameter vsession_1583, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_kybd_num_prompts"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1583
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
}

predicate func_11(Parameter vsession_1583, IfStmt target_11) {
		target_11.getCondition().(PointerFieldAccess).getTarget().getName()="userauth_kybd_num_prompts"
		and target_11.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1583
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_kybd_prompts"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1583
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_calloc")
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1583
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(SizeofTypeOperator).getValue()="16"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="userauth_kybd_num_prompts"
}

predicate func_12(Parameter vsession_1583, Variable vi_1596, RelationalOperation target_12) {
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getLesserOperand().(VariableAccess).getTarget()=vi_1596
		and target_12.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="userauth_kybd_num_prompts"
		and target_12.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1583
}

predicate func_13(Parameter vsession_1583, Variable vi_1596, ExprStmt target_13) {
		target_13.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_kybd_packet_len"
		and target_13.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1583
		and target_13.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="4"
		and target_13.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="length"
		and target_13.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="userauth_kybd_responses"
		and target_13.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1583
		and target_13.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1596
}

predicate func_14(Variable vi_1596, PostfixIncrExpr target_14) {
		target_14.getOperand().(VariableAccess).getTarget()=vi_1596
}

predicate func_15(Parameter vsession_1583, Variable vi_1596, ArrayExpr target_15) {
		target_15.getArrayBase().(PointerFieldAccess).getTarget().getName()="userauth_kybd_responses"
		and target_15.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1583
		and target_15.getArrayOffset().(VariableAccess).getTarget()=vi_1596
}

from Function func, Parameter vsession_1583, Variable vrc_1589, Variable vi_1596, BlockStmt target_3, VariableAccess target_4, BlockStmt target_5, FunctionCall target_6, ExprStmt target_7, EqualityOperation target_8, EqualityOperation target_9, ExprStmt target_10, IfStmt target_11, RelationalOperation target_12, ExprStmt target_13, PostfixIncrExpr target_14, ArrayExpr target_15
where
not func_0(vsession_1583, vrc_1589, target_5, target_6, target_7, target_8)
and not func_1(vsession_1583, target_9, target_10, target_11)
and not func_2(vsession_1583, vi_1596, target_12, target_13, target_14, target_15)
and func_3(vsession_1583, vi_1596, target_3)
and func_4(vrc_1589, target_5, target_4)
and func_5(vsession_1583, target_5)
and func_6(vsession_1583, target_6)
and func_7(vsession_1583, target_7)
and func_8(vrc_1589, target_8)
and func_9(vsession_1583, target_9)
and func_10(vsession_1583, target_10)
and func_11(vsession_1583, target_11)
and func_12(vsession_1583, vi_1596, target_12)
and func_13(vsession_1583, vi_1596, target_13)
and func_14(vi_1596, target_14)
and func_15(vsession_1583, vi_1596, target_15)
and vsession_1583.getType().hasName("LIBSSH2_SESSION *")
and vrc_1589.getType().hasName("int")
and vi_1596.getType().hasName("unsigned int")
and vsession_1583.getParentScope+() = func
and vrc_1589.getParentScope+() = func
and vi_1596.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
