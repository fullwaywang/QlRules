/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-userauth_list
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/userauth-list
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/userauth.c-userauth_list CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsession_63, Variable vrc_72, BlockStmt target_4, ExprStmt target_5, ExprStmt target_6, EqualityOperation target_7) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vrc_72
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="userauth_list_data_len"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_7.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsession_63, EqualityOperation target_8, ExprStmt target_9, PointerArithmeticOperation target_10) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="userauth_list_data_len"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="5"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userauth_list_data"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_list_data"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_63
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected packet size"
		and target_1.getThen().(BlockStmt).getStmt(3).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vsession_63, Variable vmethods_len_70, EqualityOperation target_8, PointerArithmeticOperation target_10, ExprStmt target_11, ExprStmt target_12) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmethods_len_70
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="userauth_list_data_len"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="5"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_63
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-41"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected userauth list size"
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vrc_72, BlockStmt target_4, VariableAccess target_3) {
		target_3.getTarget()=vrc_72
		and target_3.getParent().(IfStmt).getThen()=target_4
}

predicate func_4(Parameter vsession_63, Variable vrc_72, BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_63
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrc_72
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Failed getting response"
		and target_4.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_list_state"
		and target_4.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
}

predicate func_5(Parameter vsession_63, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_63
		and target_5.getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-37"
		and target_5.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Would block requesting userauth list"
}

predicate func_6(Parameter vsession_63, Variable vrc_72, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_63
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrc_72
		and target_6.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Failed getting response"
}

predicate func_7(Variable vrc_72, EqualityOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vrc_72
		and target_7.getAnOperand().(UnaryMinusExpr).getValue()="-37"
}

predicate func_8(Parameter vsession_63, EqualityOperation target_8) {
		target_8.getAnOperand().(PointerFieldAccess).getTarget().getName()="userauth_list_state"
		and target_8.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
}

predicate func_9(Parameter vsession_63, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_list_state"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
}

predicate func_10(Parameter vsession_63, PointerArithmeticOperation target_10) {
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="userauth_list_data"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
		and target_10.getAnOperand().(Literal).getValue()="1"
}

predicate func_11(Parameter vsession_63, Variable vmethods_len_70, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("memmove")
		and target_11.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userauth_list_data"
		and target_11.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
		and target_11.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="userauth_list_data"
		and target_11.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
		and target_11.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="5"
		and target_11.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vmethods_len_70
}

predicate func_12(Parameter vsession_63, Variable vmethods_len_70, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmethods_len_70
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="userauth_list_data"
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
}

from Function func, Parameter vsession_63, Variable vmethods_len_70, Variable vrc_72, VariableAccess target_3, BlockStmt target_4, ExprStmt target_5, ExprStmt target_6, EqualityOperation target_7, EqualityOperation target_8, ExprStmt target_9, PointerArithmeticOperation target_10, ExprStmt target_11, ExprStmt target_12
where
not func_0(vsession_63, vrc_72, target_4, target_5, target_6, target_7)
and not func_1(vsession_63, target_8, target_9, target_10)
and not func_2(vsession_63, vmethods_len_70, target_8, target_10, target_11, target_12)
and func_3(vrc_72, target_4, target_3)
and func_4(vsession_63, vrc_72, target_4)
and func_5(vsession_63, target_5)
and func_6(vsession_63, vrc_72, target_6)
and func_7(vrc_72, target_7)
and func_8(vsession_63, target_8)
and func_9(vsession_63, target_9)
and func_10(vsession_63, target_10)
and func_11(vsession_63, vmethods_len_70, target_11)
and func_12(vsession_63, vmethods_len_70, target_12)
and vsession_63.getType().hasName("LIBSSH2_SESSION *")
and vmethods_len_70.getType().hasName("unsigned long")
and vrc_72.getType().hasName("int")
and vsession_63.getParentScope+() = func
and vmethods_len_70.getParentScope+() = func
and vrc_72.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
