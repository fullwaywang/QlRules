/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_lookup_stateid
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-lookup-stateid
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_lookup_stateid 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getStmt(1)=target_0)
}

predicate func_5(Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue() instanceof PointerDereferenceExpr
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("nfs4_stid *")
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_5))
}

predicate func_6(Parameter vcstate_6147, Parameter vstateid_6148, Parameter vtypemask_6148, Parameter vs_6149) {
	exists(PointerDereferenceExpr target_6 |
		target_6.getOperand().(VariableAccess).getTarget()=vs_6149
		and target_6.getParent().(AssignExpr).getLValue() = target_6
		and target_6.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("find_stateid_by_type")
		and target_6.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="clp"
		and target_6.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcstate_6147
		and target_6.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstateid_6148
		and target_6.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtypemask_6148)
}

predicate func_7(Parameter vs_6149) {
	exists(PointerDereferenceExpr target_7 |
		target_7.getOperand().(VariableAccess).getTarget()=vs_6149
		and target_7.getParent().(NotExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_bswap32"))
}

from Function func, Parameter vcstate_6147, Parameter vstateid_6148, Parameter vtypemask_6148, Parameter vs_6149
where
not func_0(func)
and not func_5(func)
and func_6(vcstate_6147, vstateid_6148, vtypemask_6148, vs_6149)
and func_7(vs_6149)
and vcstate_6147.getType().hasName("nfsd4_compound_state *")
and vstateid_6148.getType().hasName("stateid_t *")
and vtypemask_6148.getType().hasName("unsigned char")
and vs_6149.getType().hasName("nfs4_stid **")
and vcstate_6147.getParentScope+() = func
and vstateid_6148.getParentScope+() = func
and vtypemask_6148.getParentScope+() = func
and vs_6149.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
