/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-userauth_password
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/userauth-password
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/userauth.c-userauth_password CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsession_197, VariableAccess target_29, FunctionCall target_30, LogicalOrExpr target_9) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="userauth_pswd_data_len"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_197
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected packet size"
		and target_0.getParent().(IfStmt).getCondition()=target_29
		and target_30.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_1(Parameter vsession_197, LogicalOrExpr target_7, ExprStmt target_8, LogicalOrExpr target_9) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_197
		and target_1.getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected packet size"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_2(Parameter vsession_197, BlockStmt target_31, ExprStmt target_32, LogicalOrExpr target_7) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(PointerFieldAccess).getTarget().getName()="userauth_pswd_data_len"
		and target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_2.getGreaterOperand().(Literal).getValue()="1"
		and target_2.getParent().(IfStmt).getThen()=target_31
		and target_32.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vsession_197, LogicalOrExpr target_9) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pswd_state"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9)
}

predicate func_4(Parameter vsession_197, LogicalOrExpr target_9, EqualityOperation target_33) {
	exists(ReturnStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_197
		and target_4.getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_4.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected packet size"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_33.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vusername_len_198, Parameter vpassword_len_199, Variable vs_202, EqualityOperation target_11, ExprStmt target_34, ExprStmt target_14, ExprStmt target_35, AddressOfExpr target_36) {
	exists(IfStmt target_5 |
		target_5.getCondition() instanceof EqualityOperation
		and target_5.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_5.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vusername_len_198
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vpassword_len_199
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="44"
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getValue()="4294967295"
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_202
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pswd_data_len"
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getThen().(BlockStmt).getStmt(3) instanceof IfStmt
		and target_5.getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_5.getThen().(BlockStmt).getStmt(5) instanceof ExprStmt
		and target_5.getThen().(BlockStmt).getStmt(6) instanceof ExprStmt
		and target_5.getThen().(BlockStmt).getStmt(7) instanceof ExprStmt
		and target_5.getThen().(BlockStmt).getStmt(8) instanceof ExprStmt
		and target_5.getThen().(BlockStmt).getStmt(9) instanceof ExprStmt
		and target_5.getThen().(BlockStmt).getStmt(10) instanceof ExprStmt
		and target_5.getThen().(BlockStmt).getStmt(11) instanceof ExprStmt
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_34.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_35.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_36.getOperand().(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vsession_197, ExprStmt target_37, ExprStmt target_27, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pswd_state"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_6)
		and target_37.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_27.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vsession_197, BlockStmt target_31, LogicalOrExpr target_7) {
		target_7.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="userauth_pswd_data"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="60"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="userauth_pswd_data0"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="60"
		and target_7.getParent().(IfStmt).getThen()=target_31
}

predicate func_8(Parameter vsession_197, LogicalOrExpr target_7, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pswd_data0"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="60"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
}

predicate func_9(Parameter vsession_197, BlockStmt target_38, LogicalOrExpr target_9) {
		target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="userauth_pswd_state"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="userauth_pswd_state"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_9.getParent().(IfStmt).getThen()=target_38
}

predicate func_10(Parameter vsession_197, LogicalOrExpr target_9, IfStmt target_10) {
		target_10.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="userauth_pswd_state"
		and target_10.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_10.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).toString() = "{ ... }"
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userauth_pswd_data"
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_10.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pswd_data"
		and target_10.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_10.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_11(Parameter vsession_197, BlockStmt target_39, EqualityOperation target_11) {
		target_11.getAnOperand().(PointerFieldAccess).getTarget().getName()="userauth_pswd_state"
		and target_11.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_11.getParent().(IfStmt).getThen()=target_39
}

predicate func_12(Parameter vsession_197, Parameter vpasswd_change_cb_200, EqualityOperation target_11, ExprStmt target_12) {
		target_12.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vpasswd_change_cb_200
		and target_12.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vsession_197
		and target_12.getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="userauth_pswd_newpw"
		and target_12.getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_12.getExpr().(VariableCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="userauth_pswd_newpw_len"
		and target_12.getExpr().(VariableCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_12.getExpr().(VariableCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
		and target_12.getExpr().(VariableCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_13(Parameter vsession_197, EqualityOperation target_11, IfStmt target_13) {
		target_13.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="userauth_pswd_newpw"
		and target_13.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_13.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_13.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_197
		and target_13.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-15"
		and target_13.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Password expired, and callback failed"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_14(Parameter vsession_197, Parameter vusername_len_198, Parameter vpassword_len_199, EqualityOperation target_11, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pswd_data_len"
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_14.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vusername_len_198
		and target_14.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vpassword_len_199
		and target_14.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="44"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_15(Parameter vsession_197, Variable vs_202, EqualityOperation target_11, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_202
		and target_15.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pswd_data"
		and target_15.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_15.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_15.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_15.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userauth_pswd_data_len"
		and target_15.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_15.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
		and target_15.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_16(Parameter vsession_197, EqualityOperation target_11, IfStmt target_16) {
		target_16.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="userauth_pswd_data"
		and target_16.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userauth_pswd_newpw"
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pswd_newpw"
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_16.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_16.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_197
		and target_16.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-6"
		and target_16.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unable to allocate memory for userauth password change request"
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_17(Variable vs_202, EqualityOperation target_11, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vs_202
		and target_17.getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_18(Parameter vusername_198, Parameter vusername_len_198, Variable vs_202, EqualityOperation target_11, ExprStmt target_18) {
		target_18.getExpr().(FunctionCall).getTarget().hasName("_libssh2_store_str")
		and target_18.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vs_202
		and target_18.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vusername_198
		and target_18.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vusername_len_198
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_19(Variable vs_202, EqualityOperation target_11, ExprStmt target_19) {
		target_19.getExpr().(FunctionCall).getTarget().hasName("_libssh2_store_str")
		and target_19.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vs_202
		and target_19.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ssh-connection"
		and target_19.getExpr().(FunctionCall).getArgument(2).(SubExpr).getValue()="14"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_20(Variable vs_202, EqualityOperation target_11, ExprStmt target_20) {
		target_20.getExpr().(FunctionCall).getTarget().hasName("_libssh2_store_str")
		and target_20.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vs_202
		and target_20.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="password"
		and target_20.getExpr().(FunctionCall).getArgument(2).(SubExpr).getValue()="8"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_21(Variable vs_202, EqualityOperation target_11, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vs_202
		and target_21.getExpr().(AssignExpr).getRValue().(HexLiteral).getValue()="1"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_22(Parameter vpassword_199, Parameter vpassword_len_199, Variable vs_202, EqualityOperation target_11, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("_libssh2_store_str")
		and target_22.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vs_202
		and target_22.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpassword_199
		and target_22.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpassword_len_199
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_23(Parameter vsession_197, Variable vs_202, EqualityOperation target_11, ExprStmt target_23) {
		target_23.getExpr().(FunctionCall).getTarget().hasName("_libssh2_store_u32")
		and target_23.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vs_202
		and target_23.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="userauth_pswd_newpw_len"
		and target_23.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_24(Parameter vsession_197, EqualityOperation target_11, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pswd_state"
		and target_24.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_25(Parameter vsession_197, Variable vrc_207, VariableAccess target_28, IfStmt target_25) {
		target_25.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="userauth_pswd_state"
		and target_25.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_207
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_transport_send")
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="userauth_pswd_data"
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="userauth_pswd_data_len"
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="userauth_pswd_newpw"
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="userauth_pswd_newpw_len"
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vrc_207
		and target_25.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-37"
		and target_25.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_25.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Would block waiting"
		and target_25.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_25.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userauth_pswd_data"
		and target_25.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
		and target_25.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pswd_data"
		and target_25.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_25.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_25.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userauth_pswd_newpw"
		and target_25.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
		and target_25.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pswd_newpw"
		and target_25.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_25.getThen().(BlockStmt).getStmt(6).(IfStmt).getCondition().(VariableAccess).getTarget()=vrc_207
		and target_25.getThen().(BlockStmt).getStmt(6).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_25.getThen().(BlockStmt).getStmt(6).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(6).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unable to send userauth password-change request"
		and target_25.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pswd_state"
		and target_25.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_25.getThen().(BlockStmt).getStmt(8).(GotoStmt).toString() = "goto ..."
		and target_25.getThen().(BlockStmt).getStmt(8).(GotoStmt).getName() ="password_response"
		and target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_28
}

predicate func_26(Parameter vsession_197, LogicalOrExpr target_9, BlockStmt target_26) {
		target_26.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pswd_state"
		and target_26.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_26.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_26.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_197
		and target_26.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-15"
		and target_26.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Password Expired, and no callback specified"
		and target_26.getParent().(IfStmt).getCondition()=target_9
}

predicate func_27(Parameter vsession_197, Function func, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pswd_state"
		and target_27.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_27
}

predicate func_28(Parameter vpasswd_change_cb_200, BlockStmt target_40, VariableAccess target_28) {
		target_28.getTarget()=vpasswd_change_cb_200
		and target_28.getParent().(IfStmt).getThen()=target_40
}

predicate func_29(Variable vrc_207, VariableAccess target_29) {
		target_29.getTarget()=vrc_207
}

predicate func_30(Parameter vsession_197, Variable vrc_207, FunctionCall target_30) {
		target_30.getTarget().hasName("_libssh2_error")
		and target_30.getArgument(0).(VariableAccess).getTarget()=vsession_197
		and target_30.getArgument(1).(VariableAccess).getTarget()=vrc_207
		and target_30.getArgument(2).(StringLiteral).getValue()="Waiting for password response"
}

predicate func_31(Parameter vpasswd_change_cb_200, BlockStmt target_31) {
		target_31.getStmt(0) instanceof ExprStmt
		and target_31.getStmt(1).(IfStmt).getCondition() instanceof LogicalOrExpr
		and target_31.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_31.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vpasswd_change_cb_200
		and target_31.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition() instanceof EqualityOperation
		and target_31.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_31.getStmt(1).(IfStmt).getElse() instanceof BlockStmt
}

predicate func_32(Parameter vsession_197, ExprStmt target_32) {
		target_32.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pswd_state"
		and target_32.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
}

predicate func_33(Parameter vsession_197, EqualityOperation target_33) {
		target_33.getAnOperand().(PointerFieldAccess).getTarget().getName()="userauth_pswd_state"
		and target_33.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
}

predicate func_34(Parameter vusername_198, Parameter vusername_len_198, Variable vs_202, ExprStmt target_34) {
		target_34.getExpr().(FunctionCall).getTarget().hasName("_libssh2_store_str")
		and target_34.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vs_202
		and target_34.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vusername_198
		and target_34.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vusername_len_198
}

predicate func_35(Parameter vsession_197, Parameter vpassword_199, Parameter vpassword_len_199, Variable vrc_207, ExprStmt target_35) {
		target_35.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_207
		and target_35.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_transport_send")
		and target_35.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_197
		and target_35.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="userauth_pswd_data"
		and target_35.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_35.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="userauth_pswd_data_len"
		and target_35.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_35.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vpassword_199
		and target_35.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vpassword_len_199
}

predicate func_36(Variable vs_202, AddressOfExpr target_36) {
		target_36.getOperand().(VariableAccess).getTarget()=vs_202
}

predicate func_37(Parameter vsession_197, ExprStmt target_37) {
		target_37.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pswd_data"
		and target_37.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_197
		and target_37.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_38(Parameter vpasswd_change_cb_200, BlockStmt target_38) {
		target_38.getStmt(0) instanceof IfStmt
		and target_38.getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vpasswd_change_cb_200
		and target_38.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition() instanceof EqualityOperation
		and target_38.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_38.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_38.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_38.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_38.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(4) instanceof IfStmt
}

predicate func_39(BlockStmt target_39) {
		target_39.getStmt(0) instanceof ExprStmt
		and target_39.getStmt(1) instanceof IfStmt
		and target_39.getStmt(2) instanceof ExprStmt
		and target_39.getStmt(3) instanceof ExprStmt
		and target_39.getStmt(4) instanceof IfStmt
}

predicate func_40(BlockStmt target_40) {
		target_40.getStmt(0).(IfStmt).getCondition() instanceof EqualityOperation
		and target_40.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_40.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_40.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_40.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_40.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(4) instanceof IfStmt
}

from Function func, Parameter vsession_197, Parameter vusername_198, Parameter vusername_len_198, Parameter vpassword_199, Parameter vpassword_len_199, Parameter vpasswd_change_cb_200, Variable vs_202, Variable vrc_207, LogicalOrExpr target_7, ExprStmt target_8, LogicalOrExpr target_9, IfStmt target_10, EqualityOperation target_11, ExprStmt target_12, IfStmt target_13, ExprStmt target_14, ExprStmt target_15, IfStmt target_16, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19, ExprStmt target_20, ExprStmt target_21, ExprStmt target_22, ExprStmt target_23, ExprStmt target_24, IfStmt target_25, BlockStmt target_26, ExprStmt target_27, VariableAccess target_28, VariableAccess target_29, FunctionCall target_30, BlockStmt target_31, ExprStmt target_32, EqualityOperation target_33, ExprStmt target_34, ExprStmt target_35, AddressOfExpr target_36, ExprStmt target_37, BlockStmt target_38, BlockStmt target_39, BlockStmt target_40
where
not func_0(vsession_197, target_29, target_30, target_9)
and not func_2(vsession_197, target_31, target_32, target_7)
and not func_3(vsession_197, target_9)
and not func_4(vsession_197, target_9, target_33)
and not func_5(vusername_len_198, vpassword_len_199, vs_202, target_11, target_34, target_14, target_35, target_36)
and not func_6(vsession_197, target_37, target_27, func)
and func_7(vsession_197, target_31, target_7)
and func_8(vsession_197, target_7, target_8)
and func_9(vsession_197, target_38, target_9)
and func_10(vsession_197, target_9, target_10)
and func_11(vsession_197, target_39, target_11)
and func_12(vsession_197, vpasswd_change_cb_200, target_11, target_12)
and func_13(vsession_197, target_11, target_13)
and func_14(vsession_197, vusername_len_198, vpassword_len_199, target_11, target_14)
and func_15(vsession_197, vs_202, target_11, target_15)
and func_16(vsession_197, target_11, target_16)
and func_17(vs_202, target_11, target_17)
and func_18(vusername_198, vusername_len_198, vs_202, target_11, target_18)
and func_19(vs_202, target_11, target_19)
and func_20(vs_202, target_11, target_20)
and func_21(vs_202, target_11, target_21)
and func_22(vpassword_199, vpassword_len_199, vs_202, target_11, target_22)
and func_23(vsession_197, vs_202, target_11, target_23)
and func_24(vsession_197, target_11, target_24)
and func_25(vsession_197, vrc_207, target_28, target_25)
and func_26(vsession_197, target_9, target_26)
and func_27(vsession_197, func, target_27)
and func_28(vpasswd_change_cb_200, target_40, target_28)
and func_29(vrc_207, target_29)
and func_30(vsession_197, vrc_207, target_30)
and func_31(vpasswd_change_cb_200, target_31)
and func_32(vsession_197, target_32)
and func_33(vsession_197, target_33)
and func_34(vusername_198, vusername_len_198, vs_202, target_34)
and func_35(vsession_197, vpassword_199, vpassword_len_199, vrc_207, target_35)
and func_36(vs_202, target_36)
and func_37(vsession_197, target_37)
and func_38(vpasswd_change_cb_200, target_38)
and func_39(target_39)
and func_40(target_40)
and vsession_197.getType().hasName("LIBSSH2_SESSION *")
and vusername_198.getType().hasName("const char *")
and vusername_len_198.getType().hasName("unsigned int")
and vpassword_199.getType().hasName("const unsigned char *")
and vpassword_len_199.getType().hasName("unsigned int")
and vpasswd_change_cb_200.getType().hasName("..(*)(..)")
and vs_202.getType().hasName("unsigned char *")
and vrc_207.getType().hasName("int")
and vsession_197.getParentScope+() = func
and vusername_198.getParentScope+() = func
and vusername_len_198.getParentScope+() = func
and vpassword_199.getParentScope+() = func
and vpassword_len_199.getParentScope+() = func
and vpasswd_change_cb_200.getParentScope+() = func
and vs_202.getParentScope+() = func
and vrc_207.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
