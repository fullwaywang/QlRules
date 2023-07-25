/**
 * @name openssl-c5b831f21d0d29d1e517d139d9d101763f60c9a2-ssl3_ctrl
 * @id cpp/openssl/c5b831f21d0d29d1e517d139d9d101763f60c9a2/ssl3-ctrl
 * @description openssl-c5b831f21d0d29d1e517d139d9d101763f60c9a2-ssl/s3_lib.c-ssl3_ctrl CVE-2016-0701
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_3126, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="options"
		and target_0.getQualifier().(VariableAccess).getTarget()=vs_3126
}

predicate func_1(Variable vret_3128, NotExpr target_5, ReturnStmt target_1) {
		target_1.getExpr().(VariableAccess).getTarget()=vret_3128
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_2(Parameter vs_3126, Variable vdh_3200, IfStmt target_2) {
		target_2.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_2.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_3126
		and target_2.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1048576"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("DH_generate_key")
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdh_3200
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("DH_free")
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdh_3200
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
}

/*predicate func_3(Variable vdh_3200, NotExpr target_6, IfStmt target_3) {
		target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("DH_generate_key")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdh_3200
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("DH_free")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdh_3200
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

*/
/*predicate func_4(Variable vdh_3200, NotExpr target_5, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("DH_free")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdh_3200
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

*/
predicate func_5(NotExpr target_5) {
		target_5.getOperand() instanceof FunctionCall
}

predicate func_6(NotExpr target_6) {
		target_6.getOperand() instanceof BitwiseAndExpr
}

from Function func, Parameter vs_3126, Variable vret_3128, Variable vdh_3200, PointerFieldAccess target_0, ReturnStmt target_1, IfStmt target_2, NotExpr target_5, NotExpr target_6
where
func_0(vs_3126, target_0)
and func_1(vret_3128, target_5, target_1)
and func_2(vs_3126, vdh_3200, target_2)
and func_5(target_5)
and func_6(target_6)
and vs_3126.getType().hasName("SSL *")
and vret_3128.getType().hasName("int")
and vdh_3200.getType().hasName("DH *")
and vs_3126.getParentScope+() = func
and vret_3128.getParentScope+() = func
and vdh_3200.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
