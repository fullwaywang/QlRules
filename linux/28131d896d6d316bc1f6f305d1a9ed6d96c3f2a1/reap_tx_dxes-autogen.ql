/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-reap_tx_dxes
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/reap-tx-dxes
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-reap_tx_dxes CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vwcn_384, Variable vctl_386, Variable vinfo_387) {
	exists(IfStmt target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_387
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_387
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ieee80211_tx_status_irqsafe")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="hw"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_384
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="skb"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctl_386
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("spin_lock")
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dxe_lock"
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_384
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tx_ack_skb"
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_384
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getCondition() instanceof Literal
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).toString() = "asm statement"
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getCondition() instanceof Literal
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0) instanceof StringLiteral
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(1) instanceof Literal
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand() instanceof Literal
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="9"
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getValue()="12"
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).toString() = "asm statement"
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).toString() = "asm statement"
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ieee80211_free_txskb")
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="hw"
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_384
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tx_ack_skb"
		and target_0.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_384
		and target_0.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tx_ack_skb"
		and target_0.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_384
		and target_0.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="skb"
		and target_0.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctl_386
		and target_0.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mod_timer")
		and target_0.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tx_ack_timer"
		and target_0.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_384
		and target_0.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getType().hasName("unsigned long")
		and target_0.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(Literal).getValue()="250"
		and target_0.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(DivExpr).getRightOperand().(Literal).getValue()="10"
		and target_0.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_0.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dxe_lock"
		and target_0.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_384
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof BitwiseAndExpr)
}

predicate func_20(Parameter vwcn_384, Variable vctl_386, Variable vinfo_387) {
	exists(BitwiseAndExpr target_20 |
		target_20.getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_20.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_387
		and target_20.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ieee80211_free_txskb")
		and target_20.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="hw"
		and target_20.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_384
		and target_20.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="skb"
		and target_20.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctl_386)
}

predicate func_21(Parameter vwcn_384) {
	exists(PointerFieldAccess target_21 |
		target_21.getTarget().getName()="dev"
		and target_21.getQualifier().(VariableAccess).getTarget()=vwcn_384)
}

predicate func_22(Variable vctl_386) {
	exists(PointerFieldAccess target_22 |
		target_22.getTarget().getName()="skb"
		and target_22.getQualifier().(VariableAccess).getTarget()=vctl_386)
}

predicate func_23(Variable vinfo_387) {
	exists(PointerFieldAccess target_23 |
		target_23.getTarget().getName()="flags"
		and target_23.getQualifier().(VariableAccess).getTarget()=vinfo_387)
}

from Function func, Parameter vwcn_384, Variable vctl_386, Variable vinfo_387
where
not func_0(vwcn_384, vctl_386, vinfo_387)
and func_20(vwcn_384, vctl_386, vinfo_387)
and vwcn_384.getType().hasName("wcn36xx *")
and func_21(vwcn_384)
and vctl_386.getType().hasName("wcn36xx_dxe_ctl *")
and func_22(vctl_386)
and vinfo_387.getType().hasName("ieee80211_tx_info *")
and func_23(vinfo_387)
and vwcn_384.getParentScope+() = func
and vctl_386.getParentScope+() = func
and vinfo_387.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
