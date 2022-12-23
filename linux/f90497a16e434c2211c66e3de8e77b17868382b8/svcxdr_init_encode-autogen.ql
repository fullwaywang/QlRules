/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-svcxdr_init_encode
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/svcxdr-init-encode
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-svcxdr_init_encode 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrqstp_565) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="rq_page_end"
		and target_0.getQualifier().(VariableAccess).getTarget()=vrqstp_565)
}

predicate func_1(Function func) {
	exists(PointerArithmeticOperation target_1 |
		target_1.getAnOperand().(Literal).getValue()="1"
		and target_1.getAnOperand() instanceof PointerFieldAccess
		and target_1.getEnclosingFunction() = func)
}

from Function func, Parameter vrqstp_565
where
func_0(vrqstp_565)
and func_1(func)
and vrqstp_565.getType().hasName("svc_rqst *")
and vrqstp_565.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
