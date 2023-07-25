/**
 * @name libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-sftp_readdir
 * @id cpp/libssh2/f15b1e297f72882214988101ccdc5e6ad30d7e6e/sftp-readdir
 * @description libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-src/sftp.c-sftp_readdir CVE-2019-3862
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Variable vsession_1645, Variable vdata_len_1646, Variable vdata_1650, Variable vretcode_1653, EqualityOperation target_4, FunctionCall target_5, AddressOfExpr target_6, AddressOfExpr target_7, EqualityOperation target_8, ReturnStmt target_9, IfStmt target_3) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vretcode_1653
		and target_2.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-41"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdata_len_1646
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vdata_1650
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1645
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-31"
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Status message too short"
		and target_2.getElse() instanceof IfStmt
		and target_2.getParent().(IfStmt).getCondition()=target_4
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getArgument(0).(VariableAccess).getLocation())
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_7.getOperand().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_9.getExpr().(VariableAccess).getLocation().isBefore(target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(VariableAccess).getLocation()))
}

predicate func_3(Variable vsftp_1643, Variable vsession_1645, Variable vretcode_1653, EqualityOperation target_4, IfStmt target_3) {
		target_3.getCondition().(VariableAccess).getTarget()=vretcode_1653
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="readdir_state"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsftp_1643
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1645
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vretcode_1653
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Timeout waiting for status message"
		and target_3.getParent().(IfStmt).getCondition()=target_4
}

predicate func_4(Variable vretcode_1653, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vretcode_1653
		and target_4.getAnOperand().(UnaryMinusExpr).getValue()="-37"
}

predicate func_5(Variable vsession_1645, Variable vretcode_1653, FunctionCall target_5) {
		target_5.getTarget().hasName("_libssh2_error")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vsession_1645
		and target_5.getArgument(1).(VariableAccess).getTarget()=vretcode_1653
		and target_5.getArgument(2).(StringLiteral).getValue()="Timeout waiting for status message"
}

predicate func_6(Variable vdata_len_1646, AddressOfExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vdata_len_1646
}

predicate func_7(Variable vdata_1650, AddressOfExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget()=vdata_1650
}

predicate func_8(Variable vdata_1650, EqualityOperation target_8) {
		target_8.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_1650
		and target_8.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_8.getAnOperand().(Literal).getValue()="101"
}

predicate func_9(Variable vretcode_1653, ReturnStmt target_9) {
		target_9.getExpr().(VariableAccess).getTarget()=vretcode_1653
}

from Function func, Variable vsftp_1643, Variable vsession_1645, Variable vdata_len_1646, Variable vdata_1650, Variable vretcode_1653, IfStmt target_3, EqualityOperation target_4, FunctionCall target_5, AddressOfExpr target_6, AddressOfExpr target_7, EqualityOperation target_8, ReturnStmt target_9
where
not func_2(vsession_1645, vdata_len_1646, vdata_1650, vretcode_1653, target_4, target_5, target_6, target_7, target_8, target_9, target_3)
and func_3(vsftp_1643, vsession_1645, vretcode_1653, target_4, target_3)
and func_4(vretcode_1653, target_4)
and func_5(vsession_1645, vretcode_1653, target_5)
and func_6(vdata_len_1646, target_6)
and func_7(vdata_1650, target_7)
and func_8(vdata_1650, target_8)
and func_9(vretcode_1653, target_9)
and vsftp_1643.getType().hasName("LIBSSH2_SFTP *")
and vsession_1645.getType().hasName("LIBSSH2_SESSION *")
and vdata_len_1646.getType().hasName("size_t")
and vdata_1650.getType().hasName("unsigned char *")
and vretcode_1653.getType().hasName("ssize_t")
and vsftp_1643.getParentScope+() = func
and vsession_1645.getParentScope+() = func
and vdata_len_1646.getParentScope+() = func
and vdata_1650.getParentScope+() = func
and vretcode_1653.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
