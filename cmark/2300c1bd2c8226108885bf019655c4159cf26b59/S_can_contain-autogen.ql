/**
 * @name cmark-2300c1bd2c8226108885bf019655c4159cf26b59-S_can_contain
 * @id cpp/cmark/2300c1bd2c8226108885bf019655c4159cf26b59/S-can-contain
 * @description cmark-2300c1bd2c8226108885bf019655c4159cf26b59-src/node.c-S_can_contain CVE-2023-24824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getType().hasName("bool")
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof DoStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vnode_72, EqualityOperation target_5, FunctionCall target_6) {
	exists(Initializer target_1 |
		target_1.getExpr().(VariableAccess).getTarget()=vnode_72
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(VariableAccess).getLocation())
		and target_1.getExpr().(VariableAccess).getLocation().isBefore(target_6.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vchild_72, Variable vcur_73, Function func, DoStmt target_2) {
		target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcur_73
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcur_73
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vchild_72
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcur_73
		and target_2.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="parent"
		and target_2.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_73
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Parameter vnode_72, Variable vcur_73, VariableAccess target_3) {
		target_3.getTarget()=vnode_72
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcur_73
}

predicate func_4(Parameter vnode_72, Variable vcur_73, Function func, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcur_73
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnode_72
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Parameter vnode_72, Parameter vchild_72, EqualityOperation target_5) {
		target_5.getAnOperand().(FunctionCall).getTarget().hasName("cmark_node_mem")
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnode_72
		and target_5.getAnOperand().(FunctionCall).getTarget().hasName("cmark_node_mem")
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchild_72
}

predicate func_6(Parameter vnode_72, Parameter vchild_72, FunctionCall target_6) {
		target_6.getTarget().hasName("cmark_node_can_contain_type")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vnode_72
		and target_6.getArgument(1).(PointerFieldAccess).getTarget().getName()="type"
		and target_6.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchild_72
}

from Function func, Parameter vnode_72, Parameter vchild_72, Variable vcur_73, DoStmt target_2, VariableAccess target_3, ExprStmt target_4, EqualityOperation target_5, FunctionCall target_6
where
not func_0(func)
and not func_1(vnode_72, target_5, target_6)
and func_2(vchild_72, vcur_73, func, target_2)
and func_3(vnode_72, vcur_73, target_3)
and func_4(vnode_72, vcur_73, func, target_4)
and func_5(vnode_72, vchild_72, target_5)
and func_6(vnode_72, vchild_72, target_6)
and vnode_72.getType().hasName("cmark_node *")
and vchild_72.getType().hasName("cmark_node *")
and vcur_73.getType().hasName("cmark_node *")
and vnode_72.getParentScope+() = func
and vchild_72.getParentScope+() = func
and vcur_73.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
