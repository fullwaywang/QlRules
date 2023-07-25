/**
 * @name openssl-578b956fe741bf8e84055547b1e83c28dd902c73-BIO_vprintf
 * @id cpp/openssl/578b956fe741bf8e84055547b1e83c28dd902c73/BIO-vprintf
 * @description openssl-578b956fe741bf8e84055547b1e83c28dd902c73-BIO_vprintf CVE-2016-0799
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="770"
		and not target_0.getValue()="810"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_push_info_")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="doapr()"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="b_print.c"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vformat_757, Parameter vargs_757) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("_dopr")
		and not target_1.getTarget().hasName("CRYPTO_free")
		and target_1.getArgument(0) instanceof AddressOfExpr
		and target_1.getArgument(1) instanceof AddressOfExpr
		and target_1.getArgument(2) instanceof AddressOfExpr
		and target_1.getArgument(3) instanceof AddressOfExpr
		and target_1.getArgument(4) instanceof AddressOfExpr
		and target_1.getArgument(5).(VariableAccess).getTarget()=vformat_757
		and target_1.getArgument(6).(VariableAccess).getTarget()=vargs_757)
}

predicate func_2(Parameter vformat_757, Parameter vargs_757, Variable vdynbuf_766, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_dopr")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof AddressOfExpr
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3) instanceof AddressOfExpr
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4) instanceof AddressOfExpr
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vformat_757
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vargs_757
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdynbuf_766
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_2))
}

predicate func_5(Variable vhugebufp_764) {
	exists(AddressOfExpr target_5 |
		target_5.getOperand().(VariableAccess).getTarget()=vhugebufp_764
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_6(Variable vdynbuf_766) {
	exists(AddressOfExpr target_6 |
		target_6.getOperand().(VariableAccess).getTarget()=vdynbuf_766
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_7(Variable vhugebufsize_765) {
	exists(AddressOfExpr target_7 |
		target_7.getOperand().(VariableAccess).getTarget()=vhugebufsize_765
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_8(Variable vretlen_760) {
	exists(AddressOfExpr target_8 |
		target_8.getOperand().(VariableAccess).getTarget()=vretlen_760
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_9(Variable vignored_767) {
	exists(AddressOfExpr target_9 |
		target_9.getOperand().(VariableAccess).getTarget()=vignored_767
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_12(Variable vdynbuf_766) {
	exists(AssignExpr target_12 |
		target_12.getLValue().(VariableAccess).getTarget()=vdynbuf_766
		and target_12.getRValue().(Literal).getValue()="0")
}

from Function func, Parameter vformat_757, Parameter vargs_757, Variable vretlen_760, Variable vhugebufp_764, Variable vhugebufsize_765, Variable vdynbuf_766, Variable vignored_767
where
func_0(func)
and func_1(vformat_757, vargs_757)
and not func_2(vformat_757, vargs_757, vdynbuf_766, func)
and func_5(vhugebufp_764)
and func_6(vdynbuf_766)
and func_7(vhugebufsize_765)
and func_8(vretlen_760)
and func_9(vignored_767)
and vformat_757.getType().hasName("const char *")
and vargs_757.getType().hasName("va_list")
and vretlen_760.getType().hasName("size_t")
and vhugebufp_764.getType().hasName("char *")
and vhugebufsize_765.getType().hasName("size_t")
and vdynbuf_766.getType().hasName("char *")
and func_12(vdynbuf_766)
and vignored_767.getType().hasName("int")
and vformat_757.getParentScope+() = func
and vargs_757.getParentScope+() = func
and vretlen_760.getParentScope+() = func
and vhugebufp_764.getParentScope+() = func
and vhugebufsize_765.getParentScope+() = func
and vdynbuf_766.getParentScope+() = func
and vignored_767.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
