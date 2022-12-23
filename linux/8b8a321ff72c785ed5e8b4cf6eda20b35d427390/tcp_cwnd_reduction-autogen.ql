/**
 * @name linux-8b8a321ff72c785ed5e8b4cf6eda20b35d427390-tcp_cwnd_reduction
 * @id cpp/linux/8b8a321ff72c785ed5e8b4cf6eda20b35d427390/tcp-cwnd-reduction
 * @description linux-8b8a321ff72c785ed5e8b4cf6eda20b35d427390-tcp_cwnd_reduction 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtp_2475, Variable vnewly_acked_sacked_2478, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnewly_acked_sacked_2478
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="prior_cwnd"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtp_2475
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("bool")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("warn_slowpath_null")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("bool")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_8(Variable vtp_2475) {
	exists(PointerFieldAccess target_8 |
		target_8.getTarget().getName()="sacked_out"
		and target_8.getQualifier().(VariableAccess).getTarget()=vtp_2475)
}

from Function func, Variable vtp_2475, Variable vnewly_acked_sacked_2478
where
not func_0(vtp_2475, vnewly_acked_sacked_2478, func)
and vtp_2475.getType().hasName("tcp_sock *")
and func_8(vtp_2475)
and vnewly_acked_sacked_2478.getType().hasName("int")
and vtp_2475.getParentScope+() = func
and vnewly_acked_sacked_2478.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
