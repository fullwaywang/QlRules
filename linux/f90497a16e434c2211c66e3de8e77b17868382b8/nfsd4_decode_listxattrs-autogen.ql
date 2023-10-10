/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_listxattrs
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-decode-listxattrs
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_listxattrs 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vmaxcount_2181) {
	exists(VariableDeclarationEntry target_1 |
		target_1.getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vmaxcount_2181)
}

predicate func_3(Parameter vargp_2178) {
	exists(VariableDeclarationEntry target_3 |
		target_3.getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getTarget().hasName("svc_max_payload")
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rqstp"
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vargp_2178)
}

predicate func_8(Parameter vlistxattrs_2179, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("__memset")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlistxattrs_2179
		and target_8.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_8.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="32"
		and target_8.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vlistxattrs_2179
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_8))
}

from Function func, Parameter vlistxattrs_2179, Variable vmaxcount_2181, Variable v__UNIQUE_ID___x2475_2200, Variable v__UNIQUE_ID___y2476_2200, Parameter vargp_2178
where
func_1(vmaxcount_2181)
and func_3(vargp_2178)
and not func_8(vlistxattrs_2179, func)
and vlistxattrs_2179.getType().hasName("nfsd4_listxattrs *")
and vmaxcount_2181.getType().hasName("u32")
and vargp_2178.getType().hasName("nfsd4_compoundargs *")
and vlistxattrs_2179.getParentScope+() = func
and vmaxcount_2181.getParentScope+() = func
and v__UNIQUE_ID___x2475_2200.getParentScope+() = func
and v__UNIQUE_ID___y2476_2200.getParentScope+() = func
and vargp_2178.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
