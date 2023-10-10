/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mwifiex_usb_probe
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/mwifiex-usb-probe
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mwifiex_usb_probe CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcard_403, Function func) {
	exists(SwitchStmt target_0 |
		target_0.getExpr().(PointerFieldAccess).getTarget().getName()="usb_boot_state"
		and target_0.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcard_403
		and target_0.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="1"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rx_cmd_ep"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcard_403
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tx_cmd_ep"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcard_403
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bulk_out_maxpktsize"
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcard_403
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and target_0.getStmt().(BlockStmt).getStmt(3).(BreakStmt).toString() = "break;"
		and target_0.getStmt().(BlockStmt).getStmt(4).(SwitchCase).getExpr().(Literal).getValue()="2"
		and target_0.getStmt().(BlockStmt).getStmt(5).(BreakStmt).toString() = "break;"
		and target_0.getStmt().(BlockStmt).getStmt(6).(SwitchCase).toString() = "default: "
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(Literal).getValue()="1"
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getCondition() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).toString() = "asm statement"
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getCondition() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0) instanceof StringLiteral
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(1) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="9"
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getValue()="12"
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).toString() = "asm statement"
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).toString() = "asm statement"
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(8).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-19"
		and target_0.getStmt().(BlockStmt).getStmt(8).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_0))
}

predicate func_21(Function func) {
	exists(LabelStmt target_21 |
		target_21.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_21 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_21))
}

predicate func_22(Variable vcard_403) {
	exists(PointerFieldAccess target_22 |
		target_22.getTarget().getName()="bulk_out_maxpktsize"
		and target_22.getQualifier().(VariableAccess).getTarget()=vcard_403)
}

from Function func, Variable vcard_403
where
not func_0(vcard_403, func)
and not func_21(func)
and vcard_403.getType().hasName("usb_card_rec *")
and func_22(vcard_403)
and vcard_403.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
