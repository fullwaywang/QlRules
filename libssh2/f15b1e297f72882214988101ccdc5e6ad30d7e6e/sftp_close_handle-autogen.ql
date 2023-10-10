/**
 * @name libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-sftp_close_handle
 * @id cpp/libssh2/f15b1e297f72882214988101ccdc5e6ad30d7e6e/sftp-close-handle
 * @description libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-src/sftp.c-sftp_close_handle CVE-2019-3862
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vsession_2387, Variable vdata_len_2388, Variable vdata_2391, Variable vrc_2392, EqualityOperation target_3, ExprStmt target_4, AddressOfExpr target_5, AddressOfExpr target_6, NotExpr target_7, ReturnStmt target_8, IfStmt target_2) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vrc_2392
		and target_1.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-41"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdata_len_2388
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vdata_2391
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdata_2391
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_2387
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-31"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Packet too short in FXP_CLOSE command"
		and target_1.getElse() instanceof IfStmt
		and target_1.getParent().(IfStmt).getCondition()=target_3
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getOperand().(VariableAccess).getLocation())
		and target_8.getExpr().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(VariableAccess).getLocation()))
}

predicate func_2(Variable vsession_2387, Variable vrc_2392, EqualityOperation target_3, IfStmt target_2) {
		target_2.getCondition().(VariableAccess).getTarget()=vrc_2392
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_2387
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrc_2392
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Error waiting for status message"
		and target_2.getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(Variable vrc_2392, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vrc_2392
		and target_3.getAnOperand().(UnaryMinusExpr).getValue()="-37"
}

predicate func_4(Variable vsession_2387, Variable vrc_2392, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_2387
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrc_2392
		and target_4.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Error waiting for status message"
}

predicate func_5(Variable vdata_len_2388, AddressOfExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vdata_len_2388
}

predicate func_6(Variable vdata_2391, AddressOfExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vdata_2391
}

predicate func_7(Variable vdata_2391, NotExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget()=vdata_2391
}

predicate func_8(Variable vrc_2392, ReturnStmt target_8) {
		target_8.getExpr().(VariableAccess).getTarget()=vrc_2392
}

from Function func, Variable vsession_2387, Variable vdata_len_2388, Variable vdata_2391, Variable vrc_2392, IfStmt target_2, EqualityOperation target_3, ExprStmt target_4, AddressOfExpr target_5, AddressOfExpr target_6, NotExpr target_7, ReturnStmt target_8
where
not func_1(vsession_2387, vdata_len_2388, vdata_2391, vrc_2392, target_3, target_4, target_5, target_6, target_7, target_8, target_2)
and func_2(vsession_2387, vrc_2392, target_3, target_2)
and func_3(vrc_2392, target_3)
and func_4(vsession_2387, vrc_2392, target_4)
and func_5(vdata_len_2388, target_5)
and func_6(vdata_2391, target_6)
and func_7(vdata_2391, target_7)
and func_8(vrc_2392, target_8)
and vsession_2387.getType().hasName("LIBSSH2_SESSION *")
and vdata_len_2388.getType().hasName("size_t")
and vdata_2391.getType().hasName("unsigned char *")
and vrc_2392.getType().hasName("int")
and vsession_2387.getParentScope+() = func
and vdata_len_2388.getParentScope+() = func
and vdata_2391.getParentScope+() = func
and vrc_2392.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
