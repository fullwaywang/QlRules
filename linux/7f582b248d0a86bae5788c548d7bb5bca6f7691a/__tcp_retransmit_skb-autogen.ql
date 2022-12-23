/**
 * @name linux-7f582b248d0a86bae5788c548d7bb5bca6f7691a-__tcp_retransmit_skb
 * @id cpp/linux/7f582b248d0a86bae5788c548d7bb5bca6f7691a/__tcp_retransmit_skb
 * @description linux-7f582b248d0a86bae5788c548d7bb5bca6f7691a-__tcp_retransmit_skb 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(Literal).getValue()="1"
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getCondition() instanceof Literal
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0) instanceof StringLiteral
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(1) instanceof Literal
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand() instanceof Literal
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="9"
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getValue()="12"
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_1.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand() instanceof FunctionCall
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(ReturnStmt target_6 |
		target_6.getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_6.getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand() instanceof FunctionCall
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Parameter vskb_2812, Variable vtp_2815) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("before")
		and target_7.getArgument(0).(PointerFieldAccess).getTarget().getName()="end_seq"
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cb"
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vskb_2812
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_7.getArgument(1).(PointerFieldAccess).getTarget().getName()="snd_una"
		and target_7.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtp_2815)
}

predicate func_8(Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0).(Literal).getValue()="580"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(DoStmt target_9 |
		target_9.getCondition() instanceof Literal
		and target_9.getStmt().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_9.getStmt().(BlockStmt).getStmt(1).(AsmStmt).toString() = "asm statement"
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_9.getEnclosingFunction() = func)
}

from Function func, Parameter vskb_2812, Variable vtp_2815
where
not func_1(func)
and not func_6(func)
and func_7(vskb_2812, vtp_2815)
and func_8(func)
and func_9(func)
and vskb_2812.getType().hasName("sk_buff *")
and vtp_2815.getType().hasName("tcp_sock *")
and vskb_2812.getParentScope+() = func
and vtp_2815.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
