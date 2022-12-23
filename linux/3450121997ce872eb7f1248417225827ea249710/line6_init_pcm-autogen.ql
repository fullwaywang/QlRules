/**
 * @name linux-3450121997ce872eb7f1248417225827ea249710-line6_init_pcm
 * @id cpp/linux/3450121997ce872eb7f1248417225827ea249710/line6_init_pcm
 * @description linux-3450121997ce872eb7f1248417225827ea249710-line6_init_pcm 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vline6pcm_537, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="max_packet_size_in"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vline6pcm_537
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="max_packet_size_out"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vline6pcm_537
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_dev_err")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ifcdev"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="line6"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vline6pcm_537
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="cannot get proper max packet size\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_0))
}

predicate func_3(Variable vline6pcm_537) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="max_packet_size_out"
		and target_3.getQualifier().(VariableAccess).getTarget()=vline6pcm_537)
}

from Function func, Variable vline6pcm_537
where
not func_0(vline6pcm_537, func)
and vline6pcm_537.getType().hasName("snd_line6_pcm *")
and func_3(vline6pcm_537)
and vline6pcm_537.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
