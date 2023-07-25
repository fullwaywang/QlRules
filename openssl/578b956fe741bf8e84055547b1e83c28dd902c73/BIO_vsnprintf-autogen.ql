/**
 * @name openssl-578b956fe741bf8e84055547b1e83c28dd902c73-BIO_vsnprintf
 * @id cpp/openssl/578b956fe741bf8e84055547b1e83c28dd902c73/BIO-vsnprintf
 * @description openssl-578b956fe741bf8e84055547b1e83c28dd902c73-BIO_vsnprintf CVE-2016-0799
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vformat_801, Parameter vargs_801, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_dopr")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3) instanceof AddressOfExpr
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4) instanceof AddressOfExpr
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vformat_801
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vargs_801
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vbuf_801) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vbuf_801
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_2(Parameter vn_801) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vn_801
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_3(Variable vretlen_803) {
	exists(AddressOfExpr target_3 |
		target_3.getOperand().(VariableAccess).getTarget()=vretlen_803
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_4(Variable vtruncated_804) {
	exists(AddressOfExpr target_4 |
		target_4.getOperand().(VariableAccess).getTarget()=vtruncated_804
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="0"
		and target_5.getEnclosingFunction() = func)
}

predicate func_8(Parameter vformat_801, Parameter vargs_801, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("_dopr")
		and target_8.getExpr().(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_8.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_8.getExpr().(FunctionCall).getArgument(3) instanceof AddressOfExpr
		and target_8.getExpr().(FunctionCall).getArgument(4) instanceof AddressOfExpr
		and target_8.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vformat_801
		and target_8.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vargs_801
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

from Function func, Parameter vbuf_801, Parameter vn_801, Parameter vformat_801, Parameter vargs_801, Variable vretlen_803, Variable vtruncated_804
where
not func_0(vformat_801, vargs_801, func)
and func_1(vbuf_801)
and func_2(vn_801)
and func_3(vretlen_803)
and func_4(vtruncated_804)
and func_5(func)
and func_8(vformat_801, vargs_801, func)
and vbuf_801.getType().hasName("char *")
and vn_801.getType().hasName("size_t")
and vformat_801.getType().hasName("const char *")
and vargs_801.getType().hasName("va_list")
and vretlen_803.getType().hasName("size_t")
and vtruncated_804.getType().hasName("int")
and vbuf_801.getParentScope+() = func
and vn_801.getParentScope+() = func
and vformat_801.getParentScope+() = func
and vargs_801.getParentScope+() = func
and vretlen_803.getParentScope+() = func
and vtruncated_804.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
