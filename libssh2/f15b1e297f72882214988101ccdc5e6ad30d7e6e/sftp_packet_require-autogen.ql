/**
 * @name libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-sftp_packet_require
 * @id cpp/libssh2/f15b1e297f72882214988101ccdc5e6ad30d7e6e/sftp-packet-require
 * @description libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-src/sftp.c-sftp_packet_require CVE-2019-3862
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_506, Parameter vdata_len_507, BlockStmt target_14, EqualityOperation target_6) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdata_506
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdata_len_507
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_14
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_6, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(UnaryMinusExpr).getValue()="-39"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vdata_len_507, NotExpr target_11, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof EqualityOperation
		and target_2.getThen().(BlockStmt).getStmt(0) instanceof DoStmt
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdata_len_507
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-41"
		and target_2.getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_2)
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_11.getOperand().(FunctionCall).getArgument(4).(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vdata_len_507, BlockStmt target_15, NotExpr target_11) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdata_len_507
		and target_3.getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_3.getParent().(IfStmt).getThen()=target_15
		and target_3.getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_11.getOperand().(FunctionCall).getArgument(4).(VariableAccess).getLocation()))
}

*/
/*predicate func_4(NotExpr target_11, Function func) {
	exists(ReturnStmt target_4 |
		target_4.getExpr().(UnaryMinusExpr).getValue()="-41"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_4.getEnclosingFunction() = func)
}

*/
predicate func_5(Parameter vdata_len_507, EqualityOperation target_6) {
	exists(IfStmt target_5 |
		target_5.getCondition() instanceof NotExpr
		and target_5.getThen().(BlockStmt).getStmt(0) instanceof DoStmt
		and target_5.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdata_len_507
		and target_5.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_5.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-41"
		and target_5.getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and target_6.getAnOperand().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vsftp_505, Parameter vpacket_type_505, Parameter vrequest_id_506, Parameter vdata_506, Parameter vdata_len_507, BlockStmt target_14, EqualityOperation target_6) {
		target_6.getAnOperand().(FunctionCall).getTarget().hasName("sftp_packet_ask")
		and target_6.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsftp_505
		and target_6.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpacket_type_505
		and target_6.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vrequest_id_506
		and target_6.getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdata_506
		and target_6.getAnOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vdata_len_507
		and target_6.getAnOperand().(Literal).getValue()="0"
		and target_6.getParent().(IfStmt).getThen()=target_14
}

predicate func_7(EqualityOperation target_6, Function func, DoStmt target_7) {
		target_7.getCondition().(Literal).getValue()="0"
		and target_7.getStmt().(BlockStmt).toString() = "{ ... }"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_7.getEnclosingFunction() = func
}

predicate func_8(EqualityOperation target_6, Function func, ReturnStmt target_8) {
		target_8.getExpr().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Parameter vsftp_505, Variable vrc_510, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_510
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sftp_packet_read")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsftp_505
}

predicate func_10(Variable vrc_510, IfStmt target_10) {
		target_10.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrc_510
		and target_10.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_10.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vrc_510
}

predicate func_11(Parameter vsftp_505, Parameter vpacket_type_505, Parameter vrequest_id_506, Parameter vdata_506, Parameter vdata_len_507, BlockStmt target_15, NotExpr target_11) {
		target_11.getOperand().(FunctionCall).getTarget().hasName("sftp_packet_ask")
		and target_11.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsftp_505
		and target_11.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpacket_type_505
		and target_11.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vrequest_id_506
		and target_11.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdata_506
		and target_11.getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vdata_len_507
		and target_11.getParent().(IfStmt).getThen()=target_15
}

predicate func_12(NotExpr target_11, Function func, DoStmt target_12) {
		target_12.getCondition().(Literal).getValue()="0"
		and target_12.getStmt().(BlockStmt).toString() = "{ ... }"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_12.getEnclosingFunction() = func
}

predicate func_13(NotExpr target_11, Function func, ReturnStmt target_13) {
		target_13.getExpr().(Literal).getValue()="0"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_13.getEnclosingFunction() = func
}

predicate func_14(BlockStmt target_14) {
		target_14.getStmt(0) instanceof DoStmt
		and target_14.getStmt(1) instanceof ReturnStmt
}

predicate func_15(BlockStmt target_15) {
		target_15.getStmt(0) instanceof DoStmt
		and target_15.getStmt(1) instanceof ReturnStmt
}

from Function func, Parameter vsftp_505, Parameter vpacket_type_505, Parameter vrequest_id_506, Parameter vdata_506, Parameter vdata_len_507, Variable vrc_510, EqualityOperation target_6, DoStmt target_7, ReturnStmt target_8, ExprStmt target_9, IfStmt target_10, NotExpr target_11, DoStmt target_12, ReturnStmt target_13, BlockStmt target_14, BlockStmt target_15
where
not func_0(vdata_506, vdata_len_507, target_14, target_6)
and not func_1(target_6, func)
and not func_2(vdata_len_507, target_11, func)
and not func_5(vdata_len_507, target_6)
and func_6(vsftp_505, vpacket_type_505, vrequest_id_506, vdata_506, vdata_len_507, target_14, target_6)
and func_7(target_6, func, target_7)
and func_8(target_6, func, target_8)
and func_9(vsftp_505, vrc_510, target_9)
and func_10(vrc_510, target_10)
and func_11(vsftp_505, vpacket_type_505, vrequest_id_506, vdata_506, vdata_len_507, target_15, target_11)
and func_12(target_11, func, target_12)
and func_13(target_11, func, target_13)
and func_14(target_14)
and func_15(target_15)
and vsftp_505.getType().hasName("LIBSSH2_SFTP *")
and vpacket_type_505.getType().hasName("unsigned char")
and vrequest_id_506.getType().hasName("uint32_t")
and vdata_506.getType().hasName("unsigned char **")
and vdata_len_507.getType().hasName("size_t *")
and vrc_510.getType().hasName("int")
and vsftp_505.getParentScope+() = func
and vpacket_type_505.getParentScope+() = func
and vrequest_id_506.getParentScope+() = func
and vdata_506.getParentScope+() = func
and vdata_len_507.getParentScope+() = func
and vrc_510.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
