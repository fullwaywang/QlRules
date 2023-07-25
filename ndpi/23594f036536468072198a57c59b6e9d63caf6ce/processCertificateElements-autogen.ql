/**
 * @name ndpi-23594f036536468072198a57c59b6e9d63caf6ce-processCertificateElements
 * @id cpp/ndpi/23594f036536468072198a57c59b6e9d63caf6ce/processCertificateElements
 * @description ndpi-23594f036536468072198a57c59b6e9d63caf6ce-src/lib/protocols/tls.c-processCertificateElements CVE-2020-15474
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func, SizeofExprOperator target_1) {
		target_1.getValue()="1024"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, SizeofExprOperator target_2) {
		target_2.getValue()="1024"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, SizeofExprOperator target_3) {
		target_3.getValue()="1024"
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func, SizeofExprOperator target_4) {
		target_4.getValue()="1024"
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Function func, SizeofExprOperator target_5) {
		target_5.getValue()="1024"
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Function func, SizeofExprOperator target_6) {
		target_6.getValue()="1024"
		and target_6.getEnclosingFunction() = func
}

predicate func_19(Variable vrdnSeqBuf_238, VariableAccess target_19) {
		target_19.getTarget()=vrdnSeqBuf_238
		and target_19.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("extractRDNSequence")
		and target_19.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(3).(SizeofExprOperator).getValue()="64"
		and target_19.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(6) instanceof SizeofExprOperator
		and target_19.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(7).(StringLiteral).getValue()="CN"
}

predicate func_20(Variable vrdnSeqBuf_238, VariableAccess target_20) {
		target_20.getTarget()=vrdnSeqBuf_238
		and target_20.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("extractRDNSequence")
		and target_20.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(3).(SizeofExprOperator).getValue()="64"
		and target_20.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(6) instanceof SizeofExprOperator
		and target_20.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(7).(StringLiteral).getValue()="C"
}

predicate func_21(Variable vrdnSeqBuf_238, VariableAccess target_21) {
		target_21.getTarget()=vrdnSeqBuf_238
		and target_21.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("extractRDNSequence")
		and target_21.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(3).(SizeofExprOperator).getValue()="64"
		and target_21.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(6) instanceof SizeofExprOperator
		and target_21.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(7).(StringLiteral).getValue()="L"
}

predicate func_22(Variable vrdnSeqBuf_238, VariableAccess target_22) {
		target_22.getTarget()=vrdnSeqBuf_238
		and target_22.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("extractRDNSequence")
		and target_22.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(3).(SizeofExprOperator).getValue()="64"
		and target_22.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(6) instanceof SizeofExprOperator
		and target_22.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(7).(StringLiteral).getValue()="ST"
}

predicate func_23(Variable vrdnSeqBuf_238, VariableAccess target_23) {
		target_23.getTarget()=vrdnSeqBuf_238
		and target_23.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("extractRDNSequence")
		and target_23.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(3).(SizeofExprOperator).getValue()="64"
		and target_23.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(6) instanceof SizeofExprOperator
		and target_23.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(7).(StringLiteral).getValue()="O"
}

predicate func_24(Variable vrdnSeqBuf_238, VariableAccess target_24) {
		target_24.getTarget()=vrdnSeqBuf_238
		and target_24.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("extractRDNSequence")
		and target_24.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(3).(SizeofExprOperator).getValue()="64"
		and target_24.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(6) instanceof SizeofExprOperator
		and target_24.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(7).(StringLiteral).getValue()="OU"
}

from Function func, Variable vrdnSeqBuf_238, SizeofExprOperator target_1, SizeofExprOperator target_2, SizeofExprOperator target_3, SizeofExprOperator target_4, SizeofExprOperator target_5, SizeofExprOperator target_6, VariableAccess target_19, VariableAccess target_20, VariableAccess target_21, VariableAccess target_22, VariableAccess target_23, VariableAccess target_24
where
func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and func_5(func, target_5)
and func_6(func, target_6)
and func_19(vrdnSeqBuf_238, target_19)
and func_20(vrdnSeqBuf_238, target_20)
and func_21(vrdnSeqBuf_238, target_21)
and func_22(vrdnSeqBuf_238, target_22)
and func_23(vrdnSeqBuf_238, target_23)
and func_24(vrdnSeqBuf_238, target_24)
and vrdnSeqBuf_238.getType().hasName("char[1024]")
and vrdnSeqBuf_238.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
