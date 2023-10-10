/**
 * @name linux-4397f04575c44e1440ec2e49b6302785c95fd2f8-allocate_trace_buffer
 * @id cpp/linux/4397f04575c44e1440ec2e49b6302785c95fd2f8/allocate-trace-buffer
 * @description linux-4397f04575c44e1440ec2e49b6302785c95fd2f8-allocate_trace_buffer 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_7568) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buffer"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7568
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_7568)
}

predicate func_1(Parameter vbuf_7568) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="buffer"
		and target_1.getQualifier().(VariableAccess).getTarget()=vbuf_7568)
}

from Function func, Parameter vbuf_7568
where
not func_0(vbuf_7568)
and vbuf_7568.getType().hasName("trace_buffer *")
and func_1(vbuf_7568)
and vbuf_7568.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
