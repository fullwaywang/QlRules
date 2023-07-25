/**
 * @name libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-sftp_unlink
 * @id cpp/libssh2/f15b1e297f72882214988101ccdc5e6ad30d7e6e/sftp-unlink
 * @description libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-src/sftp.c-sftp_unlink CVE-2019-3862
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vsession_2505, Variable vdata_len_2506, Variable vdata_2510, Variable vrc_2511, EqualityOperation target_3, FunctionCall target_4, AddressOfExpr target_5, AddressOfExpr target_6, PointerArithmeticOperation target_7, ReturnStmt target_8, IfStmt target_2) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vrc_2511
		and target_1.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-41"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdata_len_2506
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vdata_2510
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_2505
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-31"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="SFTP unlink packet too short"
		and target_1.getElse() instanceof IfStmt
		and target_1.getParent().(IfStmt).getCondition()=target_3
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getArgument(0).(VariableAccess).getLocation())
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation())
		and target_8.getExpr().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(VariableAccess).getLocation()))
}

predicate func_2(Variable vsession_2505, Variable vrc_2511, Parameter vsftp_2501, EqualityOperation target_3, IfStmt target_2) {
		target_2.getCondition().(VariableAccess).getTarget()=vrc_2511
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="unlink_state"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsftp_2501
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_2505
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrc_2511
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Error waiting for FXP STATUS"
		and target_2.getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(Variable vrc_2511, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vrc_2511
		and target_3.getAnOperand().(UnaryMinusExpr).getValue()="-37"
}

predicate func_4(Variable vsession_2505, Variable vrc_2511, FunctionCall target_4) {
		target_4.getTarget().hasName("_libssh2_error")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vsession_2505
		and target_4.getArgument(1).(VariableAccess).getTarget()=vrc_2511
		and target_4.getArgument(2).(StringLiteral).getValue()="Error waiting for FXP STATUS"
}

predicate func_5(Variable vdata_len_2506, AddressOfExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vdata_len_2506
}

predicate func_6(Variable vdata_2510, AddressOfExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vdata_2510
}

predicate func_7(Variable vdata_2510, PointerArithmeticOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vdata_2510
		and target_7.getAnOperand().(Literal).getValue()="5"
}

predicate func_8(Variable vrc_2511, ReturnStmt target_8) {
		target_8.getExpr().(VariableAccess).getTarget()=vrc_2511
}

from Function func, Variable vsession_2505, Variable vdata_len_2506, Variable vdata_2510, Variable vrc_2511, Parameter vsftp_2501, IfStmt target_2, EqualityOperation target_3, FunctionCall target_4, AddressOfExpr target_5, AddressOfExpr target_6, PointerArithmeticOperation target_7, ReturnStmt target_8
where
not func_1(vsession_2505, vdata_len_2506, vdata_2510, vrc_2511, target_3, target_4, target_5, target_6, target_7, target_8, target_2)
and func_2(vsession_2505, vrc_2511, vsftp_2501, target_3, target_2)
and func_3(vrc_2511, target_3)
and func_4(vsession_2505, vrc_2511, target_4)
and func_5(vdata_len_2506, target_5)
and func_6(vdata_2510, target_6)
and func_7(vdata_2510, target_7)
and func_8(vrc_2511, target_8)
and vsession_2505.getType().hasName("LIBSSH2_SESSION *")
and vdata_len_2506.getType().hasName("size_t")
and vdata_2510.getType().hasName("unsigned char *")
and vrc_2511.getType().hasName("int")
and vsftp_2501.getType().hasName("LIBSSH2_SFTP *")
and vsession_2505.getParentScope+() = func
and vdata_len_2506.getParentScope+() = func
and vdata_2510.getParentScope+() = func
and vrc_2511.getParentScope+() = func
and vsftp_2501.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
