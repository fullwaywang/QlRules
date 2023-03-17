/**
 * @name httpd-5bc61a05cf034980a85b81188032afca58b31468-set_error_response
 * @id cpp/httpd/5bc61a05cf034980a85b81188032afca58b31468/set-error-response
 * @description httpd-5bc61a05cf034980a85b81188032afca58b31468-set_error_response CVE-2021-31618
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vstream_639, BlockStmt target_2, NotExpr target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof NotExpr
		and target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="rtmp"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstream_639
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vstream_639, BlockStmt target_2, NotExpr target_1) {
		target_1.getOperand().(FunctionCall).getTarget().hasName("h2_stream_is_ready")
		and target_1.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstream_639
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vstream_639, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="http_status"
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rtmp"
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstream_639
}

from Function func, Parameter vstream_639, NotExpr target_1, BlockStmt target_2
where
not func_0(vstream_639, target_2, target_1)
and func_1(vstream_639, target_2, target_1)
and func_2(vstream_639, target_2)
and vstream_639.getType().hasName("h2_stream *")
and vstream_639.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
