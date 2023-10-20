/**
 * @name libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-sftp_fstatvfs
 * @id cpp/libssh2/f15b1e297f72882214988101ccdc5e6ad30d7e6e/sftp-fstatvfs
 * @description libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-src/sftp.c-sftp_fstatvfs CVE-2019-3862
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vsession_2731, Variable vdata_len_2732, Variable vdata_2737, Variable vrc_2738, EqualityOperation target_3, FunctionCall target_4, AddressOfExpr target_5, RelationalOperation target_6, AddressOfExpr target_7, EqualityOperation target_8, ReturnStmt target_9, IfStmt target_2) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vrc_2738
		and target_1.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-41"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdata_len_2732
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vdata_2737
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_2731
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-31"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="SFTP rename packet too short"
		and target_1.getElse() instanceof IfStmt
		and target_1.getParent().(IfStmt).getCondition()=target_3
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getArgument(0).(VariableAccess).getLocation())
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getLesserOperand().(VariableAccess).getLocation())
		and target_7.getOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_9.getExpr().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(VariableAccess).getLocation()))
}

predicate func_2(Variable vsftp_2729, Variable vsession_2731, Variable vrc_2738, EqualityOperation target_3, IfStmt target_2) {
		target_2.getCondition().(VariableAccess).getTarget()=vrc_2738
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="fstatvfs_state"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsftp_2729
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_2731
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrc_2738
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Error waiting for FXP EXTENDED REPLY"
		and target_2.getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(Variable vrc_2738, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vrc_2738
		and target_3.getAnOperand().(UnaryMinusExpr).getValue()="-37"
}

predicate func_4(Variable vsession_2731, Variable vrc_2738, FunctionCall target_4) {
		target_4.getTarget().hasName("_libssh2_error")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vsession_2731
		and target_4.getArgument(1).(VariableAccess).getTarget()=vrc_2738
		and target_4.getArgument(2).(StringLiteral).getValue()="Error waiting for FXP EXTENDED REPLY"
}

predicate func_5(Variable vdata_len_2732, AddressOfExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vdata_len_2732
}

predicate func_6(Variable vdata_len_2732, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(VariableAccess).getTarget()=vdata_len_2732
		and target_6.getGreaterOperand().(Literal).getValue()="93"
}

predicate func_7(Variable vdata_2737, AddressOfExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget()=vdata_2737
}

predicate func_8(Variable vdata_2737, EqualityOperation target_8) {
		target_8.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_2737
		and target_8.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_8.getAnOperand().(Literal).getValue()="101"
}

predicate func_9(Variable vrc_2738, ReturnStmt target_9) {
		target_9.getExpr().(VariableAccess).getTarget()=vrc_2738
}

from Function func, Variable vsftp_2729, Variable vsession_2731, Variable vdata_len_2732, Variable vdata_2737, Variable vrc_2738, IfStmt target_2, EqualityOperation target_3, FunctionCall target_4, AddressOfExpr target_5, RelationalOperation target_6, AddressOfExpr target_7, EqualityOperation target_8, ReturnStmt target_9
where
not func_1(vsession_2731, vdata_len_2732, vdata_2737, vrc_2738, target_3, target_4, target_5, target_6, target_7, target_8, target_9, target_2)
and func_2(vsftp_2729, vsession_2731, vrc_2738, target_3, target_2)
and func_3(vrc_2738, target_3)
and func_4(vsession_2731, vrc_2738, target_4)
and func_5(vdata_len_2732, target_5)
and func_6(vdata_len_2732, target_6)
and func_7(vdata_2737, target_7)
and func_8(vdata_2737, target_8)
and func_9(vrc_2738, target_9)
and vsftp_2729.getType().hasName("LIBSSH2_SFTP *")
and vsession_2731.getType().hasName("LIBSSH2_SESSION *")
and vdata_len_2732.getType().hasName("size_t")
and vdata_2737.getType().hasName("unsigned char *")
and vrc_2738.getType().hasName("ssize_t")
and vsftp_2729.getParentScope+() = func
and vsession_2731.getParentScope+() = func
and vdata_len_2732.getParentScope+() = func
and vdata_2737.getParentScope+() = func
and vrc_2738.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
