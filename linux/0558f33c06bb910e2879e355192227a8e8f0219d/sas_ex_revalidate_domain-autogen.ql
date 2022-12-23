/**
 * @name linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_ex_revalidate_domain
 * @id cpp/linux/0558f33c06bb910e2879e355192227a8e8f0219d/sas-ex-revalidate-domain
 * @description linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_ex_revalidate_domain function
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vres_2123, Variable vdev_2124, Variable vex_2128, Variable vi_2129, Variable vphy_id_2129, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition() instanceof LogicalAndExpr
		and target_0.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="ex_dev"
		and target_0.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_2124
		and target_0.getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_2129
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="num_phys"
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vex_2128
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vphy_id_2129
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres_2123
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sas_find_bcast_phy")
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_2124
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vphy_id_2129
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vi_2129
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vphy_id_2129
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres_2123
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sas_rediscover")
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_2124
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vphy_id_2129
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_2129
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vphy_id_2129
		and target_0.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(3).(LabelStmt).toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

predicate func_1(Variable vres_2123, Variable vdev_2124) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vres_2123
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(VariableAccess).getTarget()=vdev_2124)
}

predicate func_2(Parameter vport_dev_2121, Variable vres_2123, Variable vdev_2124, Variable vex_2128, Variable vi_2129, Variable vphy_id_2129, Function func) {
	exists(WhileStmt target_2 |
		target_2.getCondition() instanceof LogicalAndExpr
		and target_2.getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="ex_dev"
		and target_2.getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_2.getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_2124
		and target_2.getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_2129
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="num_phys"
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vex_2128
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vphy_id_2129
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres_2123
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sas_find_bcast_phy")
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_2124
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vphy_id_2129
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vi_2129
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vphy_id_2129
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres_2123
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sas_rediscover")
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_2124
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vphy_id_2129
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_2129
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vphy_id_2129
		and target_2.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getStmt().(BlockStmt).getStmt(3).(LabelStmt).toString() = "label ...:"
		and target_2.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdev_2124
		and target_2.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres_2123
		and target_2.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sas_find_bcast_dev")
		and target_2.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vport_dev_2121
		and target_2.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdev_2124
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

from Function func, Parameter vport_dev_2121, Variable vres_2123, Variable vdev_2124, Variable vex_2128, Variable vi_2129, Variable vphy_id_2129
where
not func_0(vres_2123, vdev_2124, vex_2128, vi_2129, vphy_id_2129, func)
and func_1(vres_2123, vdev_2124)
and func_2(vport_dev_2121, vres_2123, vdev_2124, vex_2128, vi_2129, vphy_id_2129, func)
and vport_dev_2121.getType().hasName("domain_device *")
and vres_2123.getType().hasName("int")
and vdev_2124.getType().hasName("domain_device *")
and vex_2128.getType().hasName("expander_device *")
and vi_2129.getType().hasName("int")
and vphy_id_2129.getType().hasName("int")
and vport_dev_2121.getParentScope+() = func
and vres_2123.getParentScope+() = func
and vdev_2124.getParentScope+() = func
and vex_2128.getParentScope+() = func
and vi_2129.getParentScope+() = func
and vphy_id_2129.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
