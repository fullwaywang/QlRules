/**
 * @name linux-ff002b30181d30cdfbca316dadd099c3ca0d739c-io_req_work_drop_env
 * @id cpp/linux/ff002b30181d30cdfbca316dadd099c3ca0d739c/io-req-work-drop-env
 * @description linux-ff002b30181d30cdfbca316dadd099c3ca0d739c-io_req_work_drop_env 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vreq_912, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(ValueFieldAccess).getTarget().getName()="fs"
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="work"
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_912
		and target_0.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getTarget().getName()="fs"
		and target_0.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="work"
		and target_0.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_912
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("spin_lock")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lock"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="fs"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="work"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_912
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="users"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("fs_struct *")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("fs_struct *")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lock"
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="fs"
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="work"
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_912
		and target_0.getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(VariableAccess).getType().hasName("fs_struct *")
		and target_0.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free_fs_struct")
		and target_0.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("fs_struct *")
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_6(Parameter vreq_912) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="work"
		and target_6.getQualifier().(VariableAccess).getTarget()=vreq_912)
}

from Function func, Parameter vreq_912
where
not func_0(vreq_912, func)
and vreq_912.getType().hasName("io_kiocb *")
and func_6(vreq_912)
and vreq_912.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
