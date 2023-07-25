/**
 * @name libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-sftp_fsync
 * @id cpp/libssh2/f15b1e297f72882214988101ccdc5e6ad30d7e6e/sftp-fsync
 * @description libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-src/sftp.c-sftp_fsync CVE-2019-3862
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vsession_2076, Variable vdata_len_2080, Variable vdata_2081, Variable vrc_2082, EqualityOperation target_3, FunctionCall target_4, AddressOfExpr target_5, AddressOfExpr target_6, PointerArithmeticOperation target_7, ReturnStmt target_8, IfStmt target_2) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vrc_2082
		and target_1.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-41"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdata_len_2080
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vdata_2081
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_2076
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-31"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="SFTP fsync packet too short"
		and target_1.getElse() instanceof IfStmt
		and target_1.getParent().(IfStmt).getCondition()=target_3
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getArgument(0).(VariableAccess).getLocation())
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation())
		and target_8.getExpr().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(VariableAccess).getLocation()))
}

predicate func_2(Variable vsftp_2074, Variable vsession_2076, Variable vrc_2082, EqualityOperation target_3, IfStmt target_2) {
		target_2.getCondition().(VariableAccess).getTarget()=vrc_2082
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="fsync_state"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsftp_2074
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_2076
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrc_2082
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Error waiting for FXP EXTENDED REPLY"
		and target_2.getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(Variable vrc_2082, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vrc_2082
		and target_3.getAnOperand().(UnaryMinusExpr).getValue()="-37"
}

predicate func_4(Variable vsession_2076, Variable vrc_2082, FunctionCall target_4) {
		target_4.getTarget().hasName("_libssh2_error")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vsession_2076
		and target_4.getArgument(1).(VariableAccess).getTarget()=vrc_2082
		and target_4.getArgument(2).(StringLiteral).getValue()="Error waiting for FXP EXTENDED REPLY"
}

predicate func_5(Variable vdata_len_2080, AddressOfExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vdata_len_2080
}

predicate func_6(Variable vdata_2081, AddressOfExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vdata_2081
}

predicate func_7(Variable vdata_2081, PointerArithmeticOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vdata_2081
		and target_7.getAnOperand().(Literal).getValue()="5"
}

predicate func_8(Variable vrc_2082, ReturnStmt target_8) {
		target_8.getExpr().(VariableAccess).getTarget()=vrc_2082
}

from Function func, Variable vsftp_2074, Variable vsession_2076, Variable vdata_len_2080, Variable vdata_2081, Variable vrc_2082, IfStmt target_2, EqualityOperation target_3, FunctionCall target_4, AddressOfExpr target_5, AddressOfExpr target_6, PointerArithmeticOperation target_7, ReturnStmt target_8
where
not func_1(vsession_2076, vdata_len_2080, vdata_2081, vrc_2082, target_3, target_4, target_5, target_6, target_7, target_8, target_2)
and func_2(vsftp_2074, vsession_2076, vrc_2082, target_3, target_2)
and func_3(vrc_2082, target_3)
and func_4(vsession_2076, vrc_2082, target_4)
and func_5(vdata_len_2080, target_5)
and func_6(vdata_2081, target_6)
and func_7(vdata_2081, target_7)
and func_8(vrc_2082, target_8)
and vsftp_2074.getType().hasName("LIBSSH2_SFTP *")
and vsession_2076.getType().hasName("LIBSSH2_SESSION *")
and vdata_len_2080.getType().hasName("size_t")
and vdata_2081.getType().hasName("unsigned char *")
and vrc_2082.getType().hasName("ssize_t")
and vsftp_2074.getParentScope+() = func
and vsession_2076.getParentScope+() = func
and vdata_len_2080.getParentScope+() = func
and vdata_2081.getParentScope+() = func
and vrc_2082.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
