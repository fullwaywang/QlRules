/**
 * @name openssl-c5b831f21d0d29d1e517d139d9d101763f60c9a2-ssl3_send_server_key_exchange
 * @id cpp/openssl/c5b831f21d0d29d1e517d139d9d101763f60c9a2/ssl3-send-server-key-exchange
 * @description openssl-c5b831f21d0d29d1e517d139d9d101763f60c9a2-ssl/s3_srvr.c-ssl3_send_server_key_exchange CVE-2016-0701
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_1593, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="options"
		and target_0.getQualifier().(VariableAccess).getTarget()=vs_1593
}

predicate func_1(Variable vdh_1603, Variable vdhp_1603, Parameter vs_1593, BitwiseAndExpr target_5, IfStmt target_1) {
		target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pub_key"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdhp_1603
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="priv_key"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdhp_1603
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1593
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1048576"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("DH_generate_key")
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdh_1603
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="err"
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pub_key"
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh_1603
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BN_dup")
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pub_key"
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdhp_1603
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="priv_key"
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh_1603
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BN_dup")
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="priv_key"
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdhp_1603
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pub_key"
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh_1603
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="priv_key"
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh_1603
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="err"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

/*predicate func_2(Variable vdh_1603, Variable vdhp_1603, LogicalOrExpr target_6, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pub_key"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh_1603
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BN_dup")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pub_key"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdhp_1603
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

*/
/*predicate func_3(Variable vdh_1603, Variable vdhp_1603, LogicalOrExpr target_6, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="priv_key"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh_1603
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BN_dup")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="priv_key"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdhp_1603
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

*/
/*predicate func_4(Variable vdh_1603, LogicalOrExpr target_6, IfStmt target_4) {
		target_4.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pub_key"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh_1603
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="priv_key"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh_1603
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_4.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_4.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="err"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

*/
predicate func_5(BitwiseAndExpr target_5) {
		target_5.getRightOperand().(Literal).getValue()="8"
}

predicate func_6(LogicalOrExpr target_6) {
		target_6.getAnOperand() instanceof LogicalOrExpr
		and target_6.getAnOperand() instanceof BitwiseAndExpr
}

from Function func, Variable vdh_1603, Variable vdhp_1603, Parameter vs_1593, PointerFieldAccess target_0, IfStmt target_1, BitwiseAndExpr target_5, LogicalOrExpr target_6
where
func_0(vs_1593, target_0)
and func_1(vdh_1603, vdhp_1603, vs_1593, target_5, target_1)
and func_5(target_5)
and func_6(target_6)
and vdh_1603.getType().hasName("DH *")
and vdhp_1603.getType().hasName("DH *")
and vs_1593.getType().hasName("SSL *")
and vdh_1603.getParentScope+() = func
and vdhp_1603.getParentScope+() = func
and vs_1593.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
