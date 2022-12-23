/**
 * @name linux-5f3e2bf008c2221478101ee72f5cb4654b9fc363-__tcp_mtu_to_mss
 * @id cpp/linux/5f3e2bf008c2221478101ee72f5cb4654b9fc363/__tcp_mtu_to_mss
 * @description linux-5f3e2bf008c2221478101ee72f5cb4654b9fc363-__tcp_mtu_to_mss CVE-2019-11479
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="48"
		and not target_0.getValue()="1"
		and target_0.getParent().(LTExpr).getParent().(IfStmt).getCondition() instanceof RelationalOperation
		and target_0.getEnclosingFunction() = func)
}

predicate func_2(Variable vmss_now_1439, Parameter vsk_1435) {
	exists(BuiltInChooseExpr target_2 |
		target_2.getChild(0).(LogicalAndExpr).getValue()="0"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(NotExpr).getValue()="1"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(NotExpr).getValue()="0"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(SizeofExprOperator).getExprOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(SizeofExprOperator).getExprOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getValue()="0"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getValue()="0"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="4"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getCondition().(Literal).getValue()="8"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vmss_now_1439
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getRightOperand().(Literal).getValue()="0"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getElse().(Literal).getValue()="8"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getValue()="0"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="4"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getCondition().(Literal).getValue()="8"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="sysctl_tcp_min_snd_mss"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ipv4"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("sock_net")
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_1435
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getRightOperand().(Literal).getValue()="0"
		and target_2.getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getElse().(Literal).getValue()="8"
		and target_2.getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmss_now_1439
		and target_2.getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="sysctl_tcp_min_snd_mss"
		and target_2.getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ipv4"
		and target_2.getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("sock_net")
		and target_2.getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_1435
		and target_2.getChild(1).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vmss_now_1439
		and target_2.getChild(1).(ConditionalExpr).getElse().(ValueFieldAccess).getTarget().getName()="sysctl_tcp_min_snd_mss"
		and target_2.getChild(1).(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ipv4"
		and target_2.getChild(1).(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("sock_net")
		and target_2.getChild(1).(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_1435
		and target_2.getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vmss_now_1439
		and target_2.getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getTarget().getName()="sysctl_tcp_min_snd_mss"
		and target_2.getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ipv4"
		and target_2.getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("sock_net")
		and target_2.getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_1435
		and target_2.getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_2.getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_2.getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(ConditionalExpr).getThen().(VariableAccess).getType().hasName("int")
		and target_2.getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(ConditionalExpr).getElse().(VariableAccess).getType().hasName("int")
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmss_now_1439)
}

predicate func_7(Variable vmss_now_1439, Function func) {
	exists(IfStmt target_7 |
		target_7.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmss_now_1439
		and target_7.getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmss_now_1439
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

predicate func_8(Variable vmss_now_1439) {
	exists(AssignExpr target_8 |
		target_8.getLValue().(VariableAccess).getTarget()=vmss_now_1439
		and target_8.getRValue() instanceof Literal)
}

predicate func_9(Parameter vsk_1435) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("__sk_dst_get")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vsk_1435)
}

from Function func, Variable vmss_now_1439, Parameter vsk_1435
where
func_0(func)
and not func_2(vmss_now_1439, vsk_1435)
and func_7(vmss_now_1439, func)
and vmss_now_1439.getType().hasName("int")
and func_8(vmss_now_1439)
and vsk_1435.getType().hasName("sock *")
and func_9(vsk_1435)
and vmss_now_1439.getParentScope+() = func
and vsk_1435.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
