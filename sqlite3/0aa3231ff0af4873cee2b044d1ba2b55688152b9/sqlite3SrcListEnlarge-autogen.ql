/**
 * @name sqlite3-0aa3231ff0af4873cee2b044d1ba2b55688152b9-sqlite3SrcListEnlarge
 * @id cpp/sqlite3/0aa3231ff0af4873cee2b044d1ba2b55688152b9/sqlite3SrcListEnlarge
 * @description sqlite3-0aa3231ff0af4873cee2b044d1ba2b55688152b9-src/build.c-sqlite3SrcListEnlarge CVE-2019-5827
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vpSrc_3879, Parameter vnExtra_3880, RelationalOperation target_7, RelationalOperation target_8) {
	exists(AddExpr target_1 |
		target_1.getAnOperand().(MulExpr).getLeftOperand() instanceof Literal
		and target_1.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="nSrc"
		and target_1.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpSrc_3879
		and target_1.getAnOperand().(VariableAccess).getTarget()=vnExtra_3880
		and target_7.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vpSrc_3879, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="nSrc"
		and target_2.getQualifier().(VariableAccess).getTarget()=vpSrc_3879
}

predicate func_3(Parameter vnExtra_3880, VariableAccess target_3) {
		target_3.getTarget()=vnExtra_3880
}

predicate func_6(Parameter vpSrc_3879, Parameter vnExtra_3880, AddExpr target_6) {
		target_6.getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="nSrc"
		and target_6.getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpSrc_3879
		and target_6.getAnOperand().(MulExpr).getRightOperand() instanceof Literal
		and target_6.getAnOperand().(VariableAccess).getTarget()=vnExtra_3880
}

predicate func_7(Parameter vpSrc_3879, Parameter vnExtra_3880, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="nSrc"
		and target_7.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpSrc_3879
		and target_7.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnExtra_3880
		and target_7.getLesserOperand().(PointerFieldAccess).getTarget().getName()="nAlloc"
		and target_7.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpSrc_3879
}

predicate func_8(Parameter vpSrc_3879, Parameter vnExtra_3880, RelationalOperation target_8) {
		 (target_8 instanceof GEExpr or target_8 instanceof LEExpr)
		and target_8.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="nSrc"
		and target_8.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpSrc_3879
		and target_8.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnExtra_3880
		and target_8.getLesserOperand().(Literal).getValue()="200"
}

from Function func, Parameter vpSrc_3879, Parameter vnExtra_3880, PointerFieldAccess target_2, VariableAccess target_3, AddExpr target_6, RelationalOperation target_7, RelationalOperation target_8
where
not func_1(vpSrc_3879, vnExtra_3880, target_7, target_8)
and func_2(vpSrc_3879, target_2)
and func_3(vnExtra_3880, target_3)
and func_6(vpSrc_3879, vnExtra_3880, target_6)
and func_7(vpSrc_3879, vnExtra_3880, target_7)
and func_8(vpSrc_3879, vnExtra_3880, target_8)
and vpSrc_3879.getType().hasName("SrcList *")
and vnExtra_3880.getType().hasName("int")
and vpSrc_3879.getFunction() = func
and vnExtra_3880.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
