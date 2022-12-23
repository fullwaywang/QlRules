/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfs3svc_decode_writeargs
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfs3svc-decode-writeargs
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfs3svc_decode_writeargs 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vxdr_549, Variable vargs_551) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xdr_stream_subsegment")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vxdr_549
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="payload"
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vargs_551
		and target_0.getArgument(2).(PointerFieldAccess).getTarget().getName()="count"
		and target_0.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vargs_551)
}

predicate func_1(Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Parameter vxdr_549, Variable vargs_551
where
func_0(vxdr_549, vargs_551)
and func_1(func)
and vxdr_549.getType().hasName("xdr_stream *")
and vargs_551.getType().hasName("nfsd3_writeargs *")
and vxdr_549.getParentScope+() = func
and vargs_551.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
