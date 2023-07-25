/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-_libssh2_userauth_publickey
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/-libssh2-userauth-publickey
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/userauth.c-_libssh2_userauth_publickey CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpubkeydata_len_1046, Parameter vsession_1042, ReturnStmt target_6, RelationalOperation target_7, ExprStmt target_8) {
	exists(SubExpr target_0 |
		target_0.getLeftOperand().(VariableAccess).getTarget()=vpubkeydata_len_1046
		and target_0.getRightOperand().(Literal).getValue()="4"
		and target_0.getParent().(GTExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="userauth_pblc_method_len"
		and target_0.getParent().(GTExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1042
		and target_0.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vpubkeydata_len_1046
		and target_0.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_6
		and target_7.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(VariableAccess).getLocation())
		and target_0.getLeftOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vrc_1054, Parameter vsession_1042, BlockStmt target_9, EqualityOperation target_10, FunctionCall target_11, ExprStmt target_12) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vrc_1054
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="userauth_pblc_data_len"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1042
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen()=target_9
		and target_10.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation())
		and target_11.getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vrc_1054, Parameter vsession_1042, BlockStmt target_13, EqualityOperation target_14, FunctionCall target_15, ExprStmt target_16) {
	exists(LogicalOrExpr target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vrc_1054
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="userauth_pblc_data_len"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1042
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_2.getParent().(IfStmt).getThen()=target_13
		and target_14.getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation())
		and target_15.getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vpubkeydata_len_1046, Parameter vsession_1042, ReturnStmt target_6, VariableAccess target_3) {
		target_3.getTarget()=vpubkeydata_len_1046
		and target_3.getParent().(GTExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="userauth_pblc_method_len"
		and target_3.getParent().(GTExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1042
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_6
}

predicate func_4(Variable vrc_1054, BlockStmt target_9, VariableAccess target_4) {
		target_4.getTarget()=vrc_1054
		and target_4.getParent().(IfStmt).getThen()=target_9
}

predicate func_5(Variable vrc_1054, BlockStmt target_13, VariableAccess target_5) {
		target_5.getTarget()=vrc_1054
		and target_5.getParent().(IfStmt).getThen()=target_13
}

predicate func_6(Parameter vsession_1042, ReturnStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1042
		and target_6.getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-19"
		and target_6.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid public key"
}

predicate func_7(Parameter vpubkeydata_len_1046, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getLesserOperand().(VariableAccess).getTarget()=vpubkeydata_len_1046
		and target_7.getGreaterOperand().(Literal).getValue()="4"
}

predicate func_8(Parameter vpubkeydata_len_1046, Parameter vsession_1042, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pblc_packet_len"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1042
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="userauth_pblc_method_len"
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1042
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vpubkeydata_len_1046
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="45"
}

predicate func_9(Parameter vsession_1042, BlockStmt target_9) {
		target_9.getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_9.getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1042
		and target_9.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userauth_pblc_packet"
		and target_9.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1042
		and target_9.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
		and target_9.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1042
}

predicate func_10(Variable vrc_1054, EqualityOperation target_10) {
		target_10.getAnOperand().(VariableAccess).getTarget()=vrc_1054
		and target_10.getAnOperand().(UnaryMinusExpr).getValue()="-37"
}

predicate func_11(Parameter vsession_1042, FunctionCall target_11) {
		target_11.getTarget().hasName("_libssh2_error")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vsession_1042
		and target_11.getArgument(1).(UnaryMinusExpr).getValue()="-37"
		and target_11.getArgument(2).(StringLiteral).getValue()="Would block"
}

predicate func_12(Parameter vsession_1042, ExprStmt target_12) {
		target_12.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_12.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1042
		and target_12.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userauth_pblc_packet"
		and target_12.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1042
		and target_12.getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
		and target_12.getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1042
}

predicate func_13(Parameter vsession_1042, BlockStmt target_13) {
		target_13.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pblc_state"
		and target_13.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1042
		and target_13.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_13.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1042
		and target_13.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-19"
		and target_13.getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Waiting for publickey USERAUTH response"
}

predicate func_14(Variable vrc_1054, EqualityOperation target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=vrc_1054
		and target_14.getAnOperand().(UnaryMinusExpr).getValue()="-37"
}

predicate func_15(Parameter vsession_1042, FunctionCall target_15) {
		target_15.getTarget().hasName("_libssh2_error")
		and target_15.getArgument(0).(VariableAccess).getTarget()=vsession_1042
		and target_15.getArgument(1).(UnaryMinusExpr).getValue()="-37"
		and target_15.getArgument(2).(StringLiteral).getValue()="Would block requesting userauth list"
}

predicate func_16(Parameter vsession_1042, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_pblc_state"
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_1042
}

from Function func, Parameter vpubkeydata_len_1046, Variable vrc_1054, Parameter vsession_1042, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, ReturnStmt target_6, RelationalOperation target_7, ExprStmt target_8, BlockStmt target_9, EqualityOperation target_10, FunctionCall target_11, ExprStmt target_12, BlockStmt target_13, EqualityOperation target_14, FunctionCall target_15, ExprStmt target_16
where
not func_0(vpubkeydata_len_1046, vsession_1042, target_6, target_7, target_8)
and not func_1(vrc_1054, vsession_1042, target_9, target_10, target_11, target_12)
and not func_2(vrc_1054, vsession_1042, target_13, target_14, target_15, target_16)
and func_3(vpubkeydata_len_1046, vsession_1042, target_6, target_3)
and func_4(vrc_1054, target_9, target_4)
and func_5(vrc_1054, target_13, target_5)
and func_6(vsession_1042, target_6)
and func_7(vpubkeydata_len_1046, target_7)
and func_8(vpubkeydata_len_1046, vsession_1042, target_8)
and func_9(vsession_1042, target_9)
and func_10(vrc_1054, target_10)
and func_11(vsession_1042, target_11)
and func_12(vsession_1042, target_12)
and func_13(vsession_1042, target_13)
and func_14(vrc_1054, target_14)
and func_15(vsession_1042, target_15)
and func_16(vsession_1042, target_16)
and vpubkeydata_len_1046.getType().hasName("unsigned long")
and vrc_1054.getType().hasName("int")
and vsession_1042.getType().hasName("LIBSSH2_SESSION *")
and vpubkeydata_len_1046.getParentScope+() = func
and vrc_1054.getParentScope+() = func
and vsession_1042.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
