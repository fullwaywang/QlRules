/**
 * @name libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-sftp_packet_requirev
 * @id cpp/libssh2/f15b1e297f72882214988101ccdc5e6ad30d7e6e/sftp-packet-requirev
 * @description libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-src/sftp.c-sftp_packet_requirev CVE-2019-3862
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_546, Parameter vdata_len_547, EqualityOperation target_5, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdata_546
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdata_len_547
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-39"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0)
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

/*predicate func_1(EqualityOperation target_5, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(UnaryMinusExpr).getValue()="-39"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_1.getEnclosingFunction() = func)
}

*/
predicate func_2(Parameter vdata_len_547, EqualityOperation target_5) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdata_len_547
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-41"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5)
}

predicate func_3(Parameter vsftp_544, EqualityOperation target_5, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="requirev_start"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsftp_544
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_4(EqualityOperation target_5, Function func, ReturnStmt target_4) {
		target_4.getExpr().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Parameter vsftp_544, Parameter vdata_546, Parameter vdata_len_547, EqualityOperation target_5) {
		target_5.getAnOperand().(FunctionCall).getTarget().hasName("sftp_packet_ask")
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsftp_544
		and target_5.getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdata_546
		and target_5.getAnOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vdata_len_547
		and target_5.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vsftp_544, Parameter vdata_546, Parameter vdata_len_547, ExprStmt target_3, ReturnStmt target_4, EqualityOperation target_5
where
not func_0(vdata_546, vdata_len_547, target_5, func)
and not func_2(vdata_len_547, target_5)
and func_3(vsftp_544, target_5, target_3)
and func_4(target_5, func, target_4)
and func_5(vsftp_544, vdata_546, vdata_len_547, target_5)
and vsftp_544.getType().hasName("LIBSSH2_SFTP *")
and vdata_546.getType().hasName("unsigned char **")
and vdata_len_547.getType().hasName("size_t *")
and vsftp_544.getParentScope+() = func
and vdata_546.getParentScope+() = func
and vdata_len_547.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
