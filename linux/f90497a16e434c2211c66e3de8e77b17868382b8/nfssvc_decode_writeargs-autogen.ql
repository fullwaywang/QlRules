/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfssvc_decode_writeargs
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfssvc-decode-writeargs
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfssvc_decode_writeargs 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vxdr_320, Variable vargs_322) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xdr_stream_subsegment")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vxdr_320
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="payload"
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vargs_322
		and target_0.getArgument(2).(PointerFieldAccess).getTarget().getName()="len"
		and target_0.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vargs_322)
}

predicate func_1(Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Parameter vxdr_320, Variable vargs_322
where
func_0(vxdr_320, vargs_322)
and func_1(func)
and vxdr_320.getType().hasName("xdr_stream *")
and vargs_322.getType().hasName("nfsd_writeargs *")
and vxdr_320.getParentScope+() = func
and vargs_322.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
