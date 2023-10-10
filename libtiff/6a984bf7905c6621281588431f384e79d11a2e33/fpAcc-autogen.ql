/**
 * @name libtiff-6a984bf7905c6621281588431f384e79d11a2e33-fpAcc
 * @id cpp/libtiff/6a984bf7905c6621281588431f384e79d11a2e33/fpAcc
 * @description libtiff-6a984bf7905c6621281588431f384e79d11a2e33-libtiff/tif_predict.c-fpAcc CVE-2016-9535
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtmp_412, NotExpr target_3, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtmp_412
		and target_0.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0)
		and target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vcc_405, FunctionCall target_1) {
		target_1.getTarget().hasName("_TIFFmalloc")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vcc_405
}

predicate func_2(Function func, Initializer target_2) {
		target_2.getExpr() instanceof FunctionCall
		and target_2.getExpr().getEnclosingFunction() = func
}

predicate func_3(Variable vtmp_412, NotExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vtmp_412
}

from Function func, Parameter vcc_405, Variable vtmp_412, FunctionCall target_1, Initializer target_2, NotExpr target_3
where
not func_0(vtmp_412, target_3, func)
and func_1(vcc_405, target_1)
and func_2(func, target_2)
and func_3(vtmp_412, target_3)
and vcc_405.getType().hasName("tmsize_t")
and vtmp_412.getType().hasName("uint8 *")
and vcc_405.getFunction() = func
and vtmp_412.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
