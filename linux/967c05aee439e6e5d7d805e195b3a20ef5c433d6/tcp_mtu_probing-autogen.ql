/**
 * @name linux-967c05aee439e6e5d7d805e195b3a20ef5c433d6-tcp_mtu_probing
 * @id cpp/linux/967c05aee439e6e5d7d805e195b3a20ef5c433d6/tcp_mtu_probing
 * @description linux-967c05aee439e6e5d7d805e195b3a20ef5c433d6-tcp_mtu_probing CVE-2019-11479
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vicsk_142, Variable vnet_144, Variable vmss_145) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmss_145
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getValue()="0"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(SizeofExprOperator).getExprOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(NotExpr).getOperand().(SizeofExprOperator).getExprOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="4"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getCondition().(Literal).getValue()="8"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vmss_145
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getRightOperand().(Literal).getValue()="0"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getElse().(Literal).getValue()="8"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="4"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getCondition().(Literal).getValue()="8"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="sysctl_tcp_min_snd_mss"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ipv4"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnet_144
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getThen().(MulExpr).getRightOperand().(Literal).getValue()="0"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(0).(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(ConditionalExpr).getElse().(Literal).getValue()="8"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmss_145
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="sysctl_tcp_min_snd_mss"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ipv4"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnet_144
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vmss_145
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getElse().(ValueFieldAccess).getTarget().getName()="sysctl_tcp_min_snd_mss"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ipv4"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(1).(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnet_144
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vmss_145
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getTarget().getName()="sysctl_tcp_min_snd_mss"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ipv4"
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnet_144
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(ConditionalExpr).getThen().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(AssignExpr).getRValue().(BuiltInChooseExpr).getChild(2).(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(ConditionalExpr).getElse().(VariableAccess).getType().hasName("int")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="enabled"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="icsk_mtup"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vicsk_142)
}

predicate func_4(Variable vnet_144) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="ipv4"
		and target_4.getQualifier().(VariableAccess).getTarget()=vnet_144)
}

from Function func, Parameter vicsk_142, Variable vnet_144, Variable vmss_145
where
not func_0(vicsk_142, vnet_144, vmss_145)
and vicsk_142.getType().hasName("inet_connection_sock *")
and vnet_144.getType().hasName("const net *")
and func_4(vnet_144)
and vmss_145.getType().hasName("int")
and vicsk_142.getParentScope+() = func
and vnet_144.getParentScope+() = func
and vmss_145.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
